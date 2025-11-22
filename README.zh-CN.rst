*****************************************
Gramine 库操作系统与 Intel SGX 支持
*****************************************

.. image:: https://readthedocs.org/projects/gramine/badge/?version=latest
   :target: http://gramine.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

.. image:: https://www.bestpractices.dev/projects/8380/badge
   :target: https://www.bestpractices.dev/projects/8380
   :alt: OpenSSF Best Practices

*适用于多进程应用程序的 Linux 兼容库操作系统*


什么是 Gramine？
================

Gramine（以前称为 *Graphene*）是一个轻量级库操作系统，旨在以最少的主机要求运行单个应用程序。Gramine 可以在隔离环境中运行应用程序，其优势可与在虚拟机中运行完整操作系统相媲美——包括客户定制、易于移植到不同操作系统以及进程迁移。

Gramine 支持任何平台上的原生、未修改的 Linux 二进制文件。目前，Gramine 在 Linux 和 Linux 平台上的 Intel SGX 飞地中运行。

在不受信任的云和边缘部署中，强烈希望将整个应用程序与基础设施的其余部分隔离。Gramine 支持这种"提升和转移"范式，以最小的移植工作将未修改的应用程序引入 Intel SGX 的机密计算。Gramine 可以保护应用程序免受恶意系统堆栈的侵害。

Gramine 是一个不断发展的项目，我们拥有不断壮大的贡献者和维护者社区。代码和项目的总体方向由来自大学、大小公司以及个人的多元化贡献者群体决定。我们的目标是继续在贡献和社区采用方面实现这种增长。

请注意，Gramine 项目以前称为 Graphene。然而，"Graphene"这个名字被认为太常见，可能无法注册商标，并且与其他几个软件项目发生冲突。因此，选择了新名称"Gramine"。


Gramine 文档
============

官方 Gramine 文档可在 https://gramine.readthedocs.io 找到。以下是一些最重要页面的快速链接：

- `Gramine 安装选项
  <https://gramine.readthedocs.io/en/latest/installation.html>`__
- `运行示例应用程序
  <https://gramine.readthedocs.io/en/latest/run-sample-application.html>`__
- `完整构建说明
  <https://gramine.readthedocs.io/en/latest/devel/building.html>`__
- `Gramine 清单文件语法
  <https://gramine.readthedocs.io/en/latest/manifest-syntax.html>`__
- `Gramine 中 SGX 应用程序的性能调优和分析
  <https://gramine.readthedocs.io/en/latest/performance.html>`__
- `Gramine 中的远程认证
  <https://gramine.readthedocs.io/en/latest/attestation.html>`__


Gramine 用户
============

我们维护了一份`公司列表
<https://gramine.readthedocs.io/en/latest/gramine-users.html>`__，这些公司正在尝试将 Gramine 用于其机密计算解决方案。


获取帮助
========

如有任何问题，请使用 `GitHub Discussions
<https://github.com/gramineproject/gramine/discussions>`__ 或加入我们的
`Gitter 聊天 <https://gitter.im/gramineproject/community>`__。

对于错误报告和功能请求，请`在我们的 GitHub 仓库上发布问题
<https://github.com/gramineproject/gramine/issues>`__。

如果您更喜欢电子邮件，请发送至 users@gramineproject.io
（`公共存档 <https://groups.google.com/g/gramine-users>`__）。


报告安全问题
============

请将安全问题报告至 security@gramineproject.io。另请参阅我们的
`安全政策 <SECURITY.md>`__。


RA-TLS 快速入门
===============

本节提供 Gramine 中 RA-TLS（远程认证 TLS）配置的快速概述。

前提条件
--------

对于使用 DCAP 的 SGX 远程认证，您需要：

- **aesmd 服务**：SGX 架构飞地服务管理器
  
  - 二进制文件位置：``/opt/intel/sgx-aesm-service/aesm/aesm_service``
  - 软件包：``sgx-aesm-service``（注意：不是 ``libsgx-aesm-service``）
  - 必需插件：``libsgx-aesm-launch-plugin``、``libsgx-aesm-pce-plugin``、``libsgx-aesm-quote-ex-plugin``、``libsgx-aesm-ecdsa-plugin``

- **PCCS 服务**（可选，用于本地 quote 缓存）：
  
  - 软件包：``sgx-dcap-pccs``
  - 配置文件：``/opt/intel/sgx-dcap-pccs/config/default.json``
  - 端口：HTTP 8080，HTTPS 8081

- **QPL 配置**：Quote Provider Library
  
  - 配置文件：``/etc/sgx_default_qcnl.conf``
  - 指定 PCCS 端点或直接访问 Intel PCS

- **SGX 设备节点**：
  
  - ``/dev/sgx_enclave`` - 运行 SGX 飞地所需
  - ``/dev/sgx_provision`` - DCAP 认证所需

使用 DCAP 支持构建
------------------

要使用 DCAP 支持构建 Gramine 以支持 RA-TLS::

    meson setup build/ --buildtype=release -Ddcap=enabled
    ninja -C build/
    sudo ninja -C build/ install

``-Ddcap=enabled`` 标志对于使用 DCAP 功能编译 RA-TLS 库至关重要。

RA-TLS 库使用
-------------

Gramine 提供 ``libratls-quote-verify.so`` 用于通过 LD_PRELOAD 进行透明的 RA-TLS 验证。

**通过 GRAMINE_LD_PRELOAD 自动注入**

在运行 ``gramine-manifest`` 之前设置 ``GRAMINE_LD_PRELOAD`` 环境变量::

    export GRAMINE_LD_PRELOAD="file:/usr/local/lib/x86_64-linux-gnu/libratls-quote-verify.so"
    gramine-manifest my-app.manifest.template my-app.manifest

这会自动：

- 将库添加到 ``sgx.trusted_files``
- 将 ``loader.env.LD_PRELOAD`` 设置为库路径
- 设置 ``loader.env.RATLS_ENABLE_VERIFY=1``
- 创建必要的 ``fs.mounts`` 条目

**手动配置**

或者，在清单模板中手动配置 LD_PRELOAD::

    sgx.remote_attestation = "dcap"
    
    loader.env.LD_PRELOAD = "/usr/local/lib/x86_64-linux-gnu/libratls-quote-verify.so"
    loader.env.RATLS_ENABLE_VERIFY = "1"
    
    sgx.trusted_files = [
        "file:/usr/local/lib/x86_64-linux-gnu/libratls-quote-verify.so",
    ]

**库加载验证**

库的构造函数在加载时始终打印初始化日志，无论环境变量如何::

    [RA-TLS SO] Initializing RA-TLS Quota Verification Library (v6)
    [RA-TLS SO] Initialization complete

如果您没有看到这些日志，则 LD_PRELOAD 注入失败。

环境变量
--------

**LD_PRELOAD 库（libratls-quote-verify.so）**

- ``RATLS_ENABLE_VERIFY`` - 启用 RA-TLS quote 验证（设置为 ``1``）
- ``RATLS_REQUIRE_PEER_CERT`` - 在 TLS 握手期间要求对等证书
- ``RATLS_KEY_PATH`` - 私钥文件路径（默认：``/tmp/crt.key``）
- ``RATLS_CERT_PATH`` - 证书文件路径（默认：``/tmp/crt.crt``）
- ``RATLS_WHITELIST_CONFIG`` - SGX 测量值白名单的 Base64 编码 JSON 配置

**验证库（ra_tls_verify_dcap.so）**

SGX 测量值验证：

- ``RA_TLS_MRSIGNER`` - 期望的 MRSIGNER 值（十六进制字符串）
- ``RA_TLS_MRENCLAVE`` - 期望的 MRENCLAVE 值（十六进制字符串）
- ``RA_TLS_ISV_PROD_ID`` - 期望的 ISV_PROD_ID（十进制字符串）
- ``RA_TLS_ISV_SVN`` - 期望的 ISV_SVN（十进制字符串）

验证策略（不安全，仅用于测试）：

- ``RA_TLS_ALLOW_OUTDATED_TCB_INSECURE`` - 允许过时的 TCB（设置为 ``1``）
- ``RA_TLS_ALLOW_HW_CONFIG_NEEDED`` - 允许需要硬件配置
- ``RA_TLS_ALLOW_SW_HARDENING_NEEDED`` - 允许需要软件加固
- ``RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE`` - 允许调试飞地（设置为 ``1``）

**证书生成（ra_tls_attest.c）**

- ``RA_TLS_CERT_ALGORITHM`` - 证书算法（例如 ``secp256r1``、``secp384r1``、``rsa3072``）
- ``RA_TLS_CERT_CONFIG_B64`` - 高级证书选项的 Base64 编码 JSON 配置
- ``RA_TLS_CERT_TIMESTAMP_NOT_BEFORE`` - 证书有效期开始（YYYYMMDDhhmmss）
- ``RA_TLS_CERT_TIMESTAMP_NOT_AFTER`` - 证书有效期结束（YYYYMMDDhhmmss）

有关详细的证书配置选项，请参阅 ``tools/sgx/ra-tls/CERTIFICATE_CONFIGURATION.md``。

重要说明
--------

- **验证失败不会退出进程**：即使 RA-TLS 验证失败，应用程序也会继续运行。这允许在没有正确 SGX 配置的环境中进行测试。
- **构造函数日志始终出现**：无论 ``RATLS_ENABLE_VERIFY`` 设置如何，都会打印库初始化日志。环境变量仅控制 TLS 握手期间的验证行为。
- **默认情况下不自动注入**：您必须显式设置 ``GRAMINE_LD_PRELOAD`` 或在清单中手动配置 LD_PRELOAD。

更多信息
--------

- 完整的 RA-TLS 文档：`Documentation/attestation.rst <Documentation/attestation.rst>`__
- 证书配置指南：`tools/sgx/ra-tls/CERTIFICATE_CONFIGURATION.md <tools/sgx/ra-tls/CERTIFICATE_CONFIGURATION.md>`__
- Gramine 清单语法：https://gramine.readthedocs.io/en/latest/manifest-syntax.html
