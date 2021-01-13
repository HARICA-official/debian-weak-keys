# Goal

Generation of 2048 and 4096 bit RSA Debian weak keys on x86 and x86_64 for
the 3 cases of `~/.rnd` (rnd, noreadrnd, nornd). The incentive was
[this thread from the `servercert-wg` mailing list of the CA/B Forum](https://cabforum.org/pipermail/servercert-wg/2020-April/001830.html)

# Implementation

## Vulnerable `openssl` version

For the reproduction of the vulnerability the
[Dockerhub image of the `etch` release](https://hub.docker.com/r/debian/eol)
was used.

When using this image, you need to downgrade openssl because the package in the
main repository of the distribution contains the patched version. This can be
accomplished by downloading and installing the
[vulnerable version from the Debian archive](https://snapshot.debian.org/).

## Image for cluster runtime

In order for the production of the keys to be done "at scale" and to take
advantage of a computer cluster, we used singularity. Singularity is a docker
compatible container runtime and version 3.4.1 of it is available on our
cluster. After logging in, it can be loaded by running:

    # module load gcc/7.3.0 singularity

Singularity (like docker) has its own
[config language for building container images](https://sylabs.io/guides/3.4/user-guide/definition_files.html).
The definition file that was used is as follows:

```
BootStrap: docker
From: debian/eol:etch

%post
  apt-get -y update && apt-get install -y build-essential wget
  wget --no-check-certificate https://snapshot.debian.org/archive/debian/20080510T000000Z/pool/main/o/openssl/libssl0.9.8_0.9.8c-4etch2_amd64.deb
  wget --no-check-certificate https://snapshot.debian.org/archive/debian/20080510T000000Z/pool/main/o/openssl/openssl_0.9.8c-4etch2_amd64.deb
  apt-get remove -y wget libssl0.9.8
  dpkg -i libssl0.9.8_0.9.8c-4etch2_amd64.deb
  dpkg -i openssl_0.9.8c-4etch2_amd64.deb
  # insert source code, could also be copied from host with %files
  cat << EOF > /getpid.c
  #include <stdio.h>
  #include <stdlib.h>

  int magicpid ;

  pid_t getpid(void)
  {
  	FILE *fd;
  	unsigned int seed;

  	if(getenv("MAGICPID")) {
  		magicpid = atoi(getenv("MAGICPID"));
  		return magicpid;
  	}

  	fd = fopen("/dev/urandom", "rb");
  	fread(&seed, sizeof(seed), 1, fd);
  	fclose(fd);

  	magicpid = seed % 32768;
  	return magicpid;
  }
EOF
  cd / && gcc -fPIC -g -c -Wall getpid.c && gcc -shared -Wl,-soname,getpid.so -o getpid.so getpid.o -lc

%test
  debian_version=$(cat /etc/debian_version)
  openssl_version=$(dpkg -s openssl | awk '/^Version/ {print $NF}')
  libssl_version=$(dpkg -s libssl | awk '/^Version/ {print $NF}')
  if [ "$debian_version" == "4.0" ] ; then echo "Debian version is 4.0 as expected" ; else echo "Debian version is not 4.0" ; fi
  if [ "$openssl_version" == "0.9.8c-4etch2" ] ; then echo "openssl version is 0.9.8c-4etch2 as expected" ; else echo "openssl version is not 0.9.8c-4etch2" ; fi
  if [ -f "/getpid.so" ]; then echo "File /getpid.so exists" ; else echo "File /getpid.so does not exist" ; fi

%runscript
  export MAGICPID=$1 && export LD_PRELOAD=/getpid.so && /usr/bin/openssl genrsa $2

%labels
  Author pkoro@it.auth.gr
  Version v1.4.0
```

The image can be built with the following command (it is required to have already logged in to singularity hub with a token):

    # singularity build --remote debian_weak_openssl.sif debian_weak_openssl.def

The result of the command is the creation of a file `debian_weak_openssl.sif`
that calls openssl in a containerized environment, preloading the PID and using
the vulnerable versions of openssl and libssl, as can be seen in section
`%runscript` of the definition file. So, for example, if we run:

    # ./debian_weak_openssl.sif 1099 2048

we will generate the 2048 bit RSA key with a seed value of 1099.

## Key generation

For the generation of 2048 bit keys the following script was used:

```
#!/bin/bash
#SBATCH --time=20:00
#SBATCH --partition=batch
#SBATCH --array=0-31

export MIN=$(( 1024 * SLURM_ARRAY_TASK_ID ))
export MAX=$(( 1023 + MIN ))
export LEN=2048

for i in $(seq $MIN $MAX) ; do
  echo $i
  ./debian_weak_openssl.sif $i $LEN > rsa-${LEN}/$i.key
done
```

and for the 4096 bit ones:

```
#!/bin/bash
#SBATCH --time=2:00:00
#SBATCH --partition=batch
#SBATCH --array=0-31

export MIN=$(( 1024 * SLURM_ARRAY_TASK_ID ))
export MAX=$(( 1023 + MIN ))
export LEN=4096

for i in $(seq $MIN $MAX) ; do
  echo $i
  ./debian_weak_openssl.sif $i $LEN > rsa-${LEN}/$i.key
done
```

In both cases the generation of the keys is segmented in 32 jobs that run in
parallel, each of which produces 1024 vulnerable keys. The main difference between the two is the estimated and actual time required. The generation process for each job took ~7 minutes to generate 1024 keys with 2048 bit length, and ~30 minutes to generate 1024 keys with 4096 bit length.

All the jobs run on
[Intel Xeon E5-2630 v4](https://ark.intel.com/content/www/us/en/ark/products/92981/intel-xeon-processor-e5-2630-v4-25m-cache-2-20-ghz.html)
CPUs with hyperthreading disabled.

## rnd, noreadrnd, nornd

All the keys generated with the previous procedure are in the "`rnd`" set. The
keys in this set are produced with the `~/.rnd` file existing and readable by
`openssl`. If this file doesn't exist or isn't readable (e.g.
`chmod 000 ~/.rnd`), the key generation produces different keys that are equally
vulnerable. A slightly different approach was used to produce this new set of
keys. Specifically, a single job was used (not 32) because every time `openssl`
is executed it creates this file and that would be a problem in the cluster
environment where the jobs tun in parallel and asynchronously. Therefore, the
following script was used for the generation of 2048 bit keys:

```
#!/bin/bash
#SBATCH --time=10:00:00
#SBATCH --partition=batch

for i in $(seq 0 32767) ; do
  echo $i
  rm -f ~/.rnd && ./debian_weak_openssl.sif $i 2048 > nornd/rsa-2048/$i.key
done
```

The job completed in 3h 41m 45s on an identical CPU as previously.

Similarly, the following script was used for the generation of 4096 bit keys:

```
#!/bin/bash
#SBATCH --time=1-00:00:00
#SBATCH --partition=batch

module load gcc/7.3.0 singularity

for i in $(seq 0 32767) ; do
  echo $i
  rm -f ~/.rnd && ./debian_weak_openssl.sif $i 4096 > nornd/rsa-4096/$i.key
done
```

It completed in 16h 58m 50s.

## 32-bit

For the production of vulnerable keys on a 32-bit architecture (`i386`) the
[32-bit container of the `etch` release](https://hub.docker.com/layers/debian/eol/etch/images/sha256-e3be45fa30661c8927f72e712d8421ae9ac7c26106e7074e7e59c9df8848a383?context=explore)
was used as a base image.

The corresponding singularity image was built using the minimum possible
changes as can be seen in the diff below:

```diff
--- debian_weak_openssl.def	2020-04-26 14:45:40.191474354 +0300
+++ debian_weak_openssl_i386.def	2020-04-28 00:44:25.345611746 +0300
@@ -1,13 +1,13 @@
 BootStrap: docker
-From: debian/eol:etch
+From: debian/eol@sha256:e3be45fa30661c8927f72e712d8421ae9ac7c26106e7074e7e59c9df8848a383

 %post
   apt-get -y update && apt-get install -y build-essential wget
-  wget --no-check-certificate https://snapshot.debian.org/archive/debian/20080510T000000Z/pool/main/o/openssl/libssl0.9.8_0.9.8c-4etch2_amd64.deb
-  wget --no-check-certificate https://snapshot.debian.org/archive/debian/20080510T000000Z/pool/main/o/openssl/openssl_0.9.8c-4etch2_amd64.deb
+  wget --no-check-certificate https://snapshot.debian.org/archive/debian/20080510T000000Z/pool/main/o/openssl/libssl0.9.8_0.9.8c-4etch2_i386.deb
+  wget --no-check-certificate https://snapshot.debian.org/archive/debian/20080510T000000Z/pool/main/o/openssl/openssl_0.9.8c-4etch2_i386.deb
   apt-get remove -y wget libssl0.9.8
-  dpkg -i libssl0.9.8_0.9.8c-4etch2_amd64.deb
-  dpkg -i openssl_0.9.8c-4etch2_amd64.deb
+  dpkg -i libssl0.9.8_0.9.8c-4etch2_i386.deb
+  dpkg -i openssl_0.9.8c-4etch2_i386.deb
   # insert source code, could also be copied from host with %files
   cat << EOF > /getpid.c
   #include <stdio.h>
```

# List of jobs and generated files

| Debian OS | openssl package | Architecture | rnd value | Key size | Output folder | Job ID |
|-----------|-----------------|--------------|-----------|----------|---------------|--------|
| etch | openssl_0.9.8c-4etch2 | amd64 | rnd | 2048 | `etch/0.9.8c-4etch2/amd64/rnd/rsa-2048` | 607217 |
| etch | openssl_0.9.8c-4etch2 | amd64 | rnd | 4096 | `etch/0.9.8c-4etch2/amd64/rnd/rsa-4096` | 607402 |
| etch | openssl_0.9.8c-4etch2 | amd64 | nornd | 2048 | `etch/0.9.8c-4etch2/amd64/nornd/rsa-2048` | 607703 |
| etch | openssl_0.9.8c-4etch2 | amd64 | nornd | 4096 | `etch/0.9.8c-4etch2/amd64/nornd/rsa-4096` | 607910 |
| etch | openssl_0.9.8c-4etch2 | i386 | rnd | 2048 | `etch/0.9.8c-4etch2/i386/rnd/rsa-2048` | 608799 |
| etch | openssl_0.9.8c-4etch2 | i386 | rnd | 4096 | `etch/0.9.8c-4etch2/i386/rnd/rsa-4096` | 608831 |
| etch | openssl_0.9.8c-4etch2 | i386 | nornd | 2048 | `etch/0.9.8c-4etch2/i386/nornd/rsa-2048` | 608583 |
| etch | openssl_0.9.8c-4etch2 | i386 | nornd | 4096 | `etch/0.9.8c-4etch2/i386/nornd/rsa-4096` | 608628, 608698 |
| lenny | openssl_0.9.8g-8 | amd64 | rnd | 2048 | `lenny/openssl_0.9.8g-8/amd64/rnd/rsa-2048` | 609069 |
| lenny | openssl_0.9.8g-8 | amd64 | rnd | 4096 | `lenny/openssl_0.9.8g-8/amd64/rnd/rsa-4096` | 609078 |
| lenny | openssl_0.9.8g-8 | amd64 | noreadrnd | 2048 | `lenny/openssl_0.9.8g-8/amd64/noreadrnd/rsa-2048` | 609138 |
| lenny | openssl_0.9.8g-8 | amd64 | noreadrnd | 4096 | `lenny/openssl_0.9.8g-8/amd64/noreadrnd/rsa-4096` | 609143 |
| lenny | openssl_0.9.8g-8 | amd64 | nornd | 2048 | `lenny/openssl_0.9.8g-8/amd64/nornd/rsa-2048` | 609225 |
| lenny | openssl_0.9.8g-8 | amd64 | nornd | 4096 | `lenny/openssl_0.9.8g-8/amd64/nornd/rsa-4096` | 609233 |
| lenny | openssl_0.9.8g-8 | i386 | nornd | 2048 | `lenny/openssl_0.9.8g-8/i386/nornd/rsa-2048` | 609266 |
| lenny | openssl_0.9.8g-8 | i386 | nornd | 4096 | `lenny/openssl_0.9.8g-8/i386/nornd/rsa-4096` | 609329 |
| lenny | openssl_0.9.8g-8 | i386 | noreadrnd | 2048 | `lenny/openssl_0.9.8g-8/i386/noreadrnd/rsa-2048` | 609363 |
| lenny | openssl_0.9.8g-8 | i386 | noreadrnd | 4096 | `lenny/openssl_0.9.8g-8/i386/noreadrnd/rsa-4096` | 609377 |

The files created with the `etch` release are not included because they are
duplicates of the ones created with the `lenny` release and more specifically of
the `rnd` and `noreadrnd` variants.

Kudos to pkoro.
