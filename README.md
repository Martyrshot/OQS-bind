# OQS-Bind

OQS-BIND is a forked version of ISC's [Bind9](https://gitlab.isc.org/isc-projects/bind9) DNS software
which enables PQC DNS. The original Bind9 readme can be found [here](ORIGINAL_README.md). This fork
take advantage of [Open Quantum Safe](https://github.com/open-quantum-safe)'s
[liboqs](https://github.com/open-quantum-safe/liboqs) and [oqs-provider](https://github.com/open-quantum-safe/oqs-provider).
**NOTE:** OpenSSL 3.2 is **REQUIRED** to build and use OQS-Bind.

This project is not officially affiliated with Open Quantum Safe.

## Algorithms
Currently only DNSSEC is supported and tested with a small number of algorithms,
but DoT and DoH inprinciple should work. I plan on eventually enabling more DNSSEC PQC algorithms in the
future and automating enabling and disabling them, but for now this must be done by hand. The algorithms
we support in DNSSEC are as follows:

### DNSSEC Algorithms
|            Algorithm         | DNSSEC Algorithm ID |
| ---------------------------- | ------------------- |
|           Falcon-512         |         17          |
|           Dilithium2         |         18          |
| SPHINCS+-SHA-256-128s Simple |         19          |

We opted to start the algorithm IDs at 17 because of the discussion seen
[here](https://mailarchive.ietf.org/arch/msg/dnsop/2xKvE-g1WU5VozEDN7-h2e5y-MQ/).

### DoT/DoH Algorithms
These have not been tested, but in principle all algorithms supported by
[oqs-proivder](https://github.com/open-quantum-safe/oqs-provider) should work.

## Building

In order to build OQS-Bind, some version of OpenSSL 3.2 must be installed. At the time
of writing Beta1 just was released, so it is recommended to not use OpenSSL 3.2 as your
primary system-wide instalation of OpenSSL. Instead, installed OpenSSL 3.2 in a special
location. You can then specify the location of OpenSSL 3.2 using the `--with-openssl=<OPENSSL3.2DIR>`.
Then simply follow the regular Bind9 build instructions found [here](https://github.com/Martyrshot/OQS-bind/blob/main/doc/arm/build.inc.rst).
