*****************************************
Gramine Library OS with Intel SGX Support
*****************************************

.. image:: https://readthedocs.org/projects/gramine/badge/?version=latest
   :target: http://gramine.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

.. image:: https://www.bestpractices.dev/projects/8380/badge
   :target: https://www.bestpractices.dev/projects/8380
   :alt: OpenSSF Best Practices

*A Linux-compatible Library OS for Multi-Process Applications*


What is Gramine?
================

Gramine (formerly called *Graphene*) is a lightweight library OS, designed to
run a single application with minimal host requirements. Gramine can run
applications in an isolated environment with benefits comparable to running a
complete OS in a virtual machine -- including guest customization, ease of
porting to different OSes, and process migration.

Gramine supports native, unmodified Linux binaries on any platform. Currently,
Gramine runs on Linux and Intel SGX enclaves on Linux platforms.

In untrusted cloud and edge deployments, there is a strong desire to shield the
whole application from rest of the infrastructure. Gramine supports this “lift
and shift” paradigm for bringing unmodified applications into Confidential
Computing with Intel SGX. Gramine can protect applications from a malicious
system stack with minimal porting effort.

Gramine is a growing project and we have a growing contributor and maintainer
community. The code and overall direction of the project are determined by a
diverse group of contributors, from universities, small and large companies, as
well as individuals. Our goal is to continue this growth in both contributions
and community adoption.

Note that the Gramine project was formerly known as Graphene. However, the name
"Graphene" was deemed too common, could be impossible to trademark, and collided
with several other software projects. Thus, a new name "Gramine" was chosen.


Gramine documentation
=====================

The official Gramine documentation can be found at
https://gramine.readthedocs.io. Below are quick links to some of the most
important pages:

- `Gramine installation options
  <https://gramine.readthedocs.io/en/latest/installation.html>`__
- `Run a sample application
  <https://gramine.readthedocs.io/en/latest/run-sample-application.html>`__
- `Complete building instructions
  <https://gramine.readthedocs.io/en/latest/devel/building.html>`__
- `Gramine manifest file syntax
  <https://gramine.readthedocs.io/en/latest/manifest-syntax.html>`__
- `Performance tuning & analysis of SGX applications in Gramine
  <https://gramine.readthedocs.io/en/latest/performance.html>`__
- `Remote attestation in Gramine
  <https://gramine.readthedocs.io/en/latest/attestation.html>`__


Users of Gramine
================

We maintain `a list of companies
<https://gramine.readthedocs.io/en/latest/gramine-users.html>`__ experimenting
with Gramine for their confidential computing solutions.


Getting help
============

For any questions, please use `GitHub Discussions
<https://github.com/gramineproject/gramine/discussions>`__ or join us on our
`Gitter chat <https://gitter.im/gramineproject/community>`__.

For bug reports and feature requests, `post an issue on our GitHub repository
<https://github.com/gramineproject/gramine/issues>`__.

If you prefer emails, please send them to users@gramineproject.io
(`public archive <https://groups.google.com/g/gramine-users>`__).


Reporting security issues
=========================

Please report security issues to security@gramineproject.io. See also our
`security policy <SECURITY.md>`__.


RA-TLS Quick Start
==================

This section provides a quick overview of RA-TLS (Remote Attestation TLS) configuration in Gramine.

Prerequisites
-------------

For SGX remote attestation with DCAP, you need:

- **aesmd service**: SGX Architectural Enclave Service Manager
  
  - Binary location: ``/opt/intel/sgx-aesm-service/aesm/aesm_service``
  - Package: ``sgx-aesm-service`` (note: NOT ``libsgx-aesm-service``)
  - Required plugins: ``libsgx-aesm-launch-plugin``, ``libsgx-aesm-pce-plugin``, ``libsgx-aesm-quote-ex-plugin``, ``libsgx-aesm-ecdsa-plugin``

- **PCCS service** (optional, for local quote caching):
  
  - Package: ``sgx-dcap-pccs``
  - Configuration: ``/opt/intel/sgx-dcap-pccs/config/default.json``
  - Ports: HTTP 8080, HTTPS 8081

- **QPL configuration**: Quote Provider Library
  
  - Configuration file: ``/etc/sgx_default_qcnl.conf``
  - Specifies PCCS endpoint or direct Intel PCS access

- **SGX device nodes**:
  
  - ``/dev/sgx_enclave`` - Required for running SGX enclaves
  - ``/dev/sgx_provision`` - Required for DCAP attestation

Building with DCAP Support
---------------------------

To build Gramine with DCAP support for RA-TLS::

    meson setup build/ --buildtype=release -Ddcap=enabled
    ninja -C build/
    sudo ninja -C build/ install

The ``-Ddcap=enabled`` flag is essential for compiling RA-TLS libraries with DCAP functionality.

RA-TLS Library Usage
---------------------

Gramine provides ``libratls-quote-verify.so`` for transparent RA-TLS verification via LD_PRELOAD.

**Automatic Injection via GRAMINE_LD_PRELOAD**

Set the ``GRAMINE_LD_PRELOAD`` environment variable before running ``gramine-manifest``::

    export GRAMINE_LD_PRELOAD="file:/usr/local/lib/x86_64-linux-gnu/libratls-quote-verify.so"
    gramine-manifest my-app.manifest.template my-app.manifest

This automatically:

- Adds the library to ``sgx.trusted_files``
- Sets ``loader.env.LD_PRELOAD`` to the library path
- Sets ``loader.env.RA_TLS_ENABLE_VERIFY=1``
- Creates necessary ``fs.mounts`` entries

**Manual Configuration**

Alternatively, configure LD_PRELOAD manually in your manifest template::

    sgx.remote_attestation = "dcap"
    
    loader.env.LD_PRELOAD = "/usr/local/lib/x86_64-linux-gnu/libratls-quote-verify.so"
    loader.env.RA_TLS_ENABLE_VERIFY = "1"
    
    sgx.trusted_files = [
        "file:/usr/local/lib/x86_64-linux-gnu/libratls-quote-verify.so",
    ]

**Library Loading Verification**

The library's constructor function always prints initialization logs when loaded, regardless of environment variables::

    [RA-TLS SO] Initializing RA-TLS Quota Verification Library (v6)
    [RA-TLS SO] Initialization complete

If you don't see these logs, LD_PRELOAD injection failed.

Environment Variables
---------------------

**LD_PRELOAD Library (libratls-quote-verify.so)**

- ``RA_TLS_ENABLE_VERIFY`` - Enable RA-TLS quote verification (set to ``1``)
- ``RA_TLS_REQUIRE_PEER_CERT`` - Require peer certificates during TLS handshakes
- ``RA_TLS_KEY_PATH`` - Path to private key file (default: ``/tmp/priv.key``)
- ``RA_TLS_CERT_PATH`` - Path to certificate file (default: ``/tmp/crt.crt``)
- ``RA_TLS_WHITELIST_CONFIG`` - Base64-encoded CSV whitelist for SGX measurements (5 lines: MRENCLAVE, MRSIGNER, ISV_PROD_ID, ISV_SVN, PLATFORM_INSTANCE_ID). Each line contains comma-separated hex values. Empty lines or ``0`` tokens act as wildcards. Hex comparison is case-insensitive.

**Verification Library (ra_tls_verify_dcap.so)**

SGX measurement verification:

- ``RA_TLS_MRSIGNER`` - Expected MRSIGNER value (hex string)
- ``RA_TLS_MRENCLAVE`` - Expected MRENCLAVE value (hex string)
- ``RA_TLS_ISV_PROD_ID`` - Expected ISV_PROD_ID (decimal string)
- ``RA_TLS_ISV_SVN`` - Expected ISV_SVN (decimal string)

Verification policy (insecure, testing only):

- ``RA_TLS_ALLOW_OUTDATED_TCB_INSECURE`` - Allow outdated TCB (set to ``1``)
- ``RA_TLS_ALLOW_HW_CONFIG_NEEDED`` - Allow hardware configuration needed
- ``RA_TLS_ALLOW_SW_HARDENING_NEEDED`` - Allow software hardening needed
- ``RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE`` - Allow debug enclaves (set to ``1``)

**Certificate Generation (ra_tls_attest.c)**

- ``RA_TLS_CERT_ALGORITHM`` - Certificate algorithm (e.g., ``secp256r1``, ``secp384r1``, ``secp521r1``, ``rsa2048``, ``rsa3072``, ``rsa4096``). Overrides JSON configuration if set.
- ``RA_TLS_CERT_CONFIG_B64`` - Base64-encoded JSON for advanced certificate configuration. Ignored if ``RA_TLS_CERT_ALGORITHM`` is set. JSON fields: ``key_file``, ``key_format`` (pem/der), ``algorithm``, ``subject``, ``not_before``, ``not_after``, ``signature_md`` (sha256/sha384/sha512), ``is_ca``, ``ca_key_file``, ``ca_key_format``, ``ca_algorithm``, ``ca_cert_file``, ``ca_cert_format``, ``ca_subject``, ``ca_not_before``, ``ca_not_after``.
- ``RA_TLS_CERT_TIMESTAMP_NOT_BEFORE`` - Certificate validity start (YYYYMMDDhhmmss format)
- ``RA_TLS_CERT_TIMESTAMP_NOT_AFTER`` - Certificate validity end (YYYYMMDDhhmmss format)

Important Notes
---------------

- **Verification failures do not exit the process**: Even if RA-TLS verification fails, the application continues running. This allows testing in environments without proper SGX configuration.
- **Constructor logs always appear**: The library initialization logs are printed regardless of ``RA_TLS_ENABLE_VERIFY`` setting. Environment variables only control verification behavior during TLS handshakes.
- **No auto-injection by default**: You must explicitly set ``GRAMINE_LD_PRELOAD`` or manually configure LD_PRELOAD in your manifest.

For More Information
--------------------

- Complete RA-TLS documentation: `Documentation/attestation.rst <Documentation/attestation.rst>`__
- Certificate configuration guide: `tools/sgx/ra-tls/CERTIFICATE_CONFIGURATION.md <tools/sgx/ra-tls/CERTIFICATE_CONFIGURATION.md>`__
- Gramine manifest syntax: https://gramine.readthedocs.io/en/latest/manifest-syntax.html
