<h2 align="center">BUPT 疫情防控通 自动上报脚本</h2>
<p align="center">
    <a href="https://github.com/ipid/bupt-ncov-report/actions">
        <img src="https://github.com/ipid/bupt-ncov-report/workflows/mypy/badge.svg" alt="mypy徽章">
    </a>
    <a href="https://github.com/ipid/bupt-ncov-report/actions">
        <img src="https://github.com/ipid/bupt-ncov-report/workflows/%E5%8D%95%E5%85%83&%E5%8A%9F%E8%83%BD%E6%B5%8B%E8%AF%95%20%20%20%20%20/badge.svg" alt="单元&amp;功能测试">
    </a>
    <a href="https://coveralls.io/github/ipid/bupt-ncov-report?branch=master">
        <img src="https://coveralls.io/repos/github/ipid/bupt-ncov-report/badge.svg?branch=master">
    </a>
    <img src="https://img.shields.io/badge/python-%3e%3d%203.6-blue" alt="Python 版本">
</p>

该脚本可以帮助您操作北邮「疫情防控通」、「晨午晚检」，自动完成每日上报。

本工具尚未实现自动更新，所以需要用户频繁更新。如果您不喜欢这一点，有一款 Telegram 机器人 ([链接](https://t.me/buptncovbot)，[以 GNUv3 授权的源代码](https://github.com/Henryzhao96/bupt-ncov-report-tgbot)）提供自动上报服务，欢迎使用。

<br>

## 特性

- 当检测到您自动上报的数据，表明您为**疑似病患**时，只要您开启了一个选项（见下方），就能**阻止上报**，防止您引起学校注意。
- 既可以部署在服务器上，也可以部署在 GCP Cloud Function、AWS Lambda 或阿里云、腾讯云云函数等支持 Python 的云函数平台上。
- 上报完成后，可通过**微信**和 **Telegram 机器人**来接收上报结果，仅需手机就能知道上报是否成功

![Telegram](https://i.imgur.com/jrQaZ9s.png) ![Server酱](https://i.imgur.com/tuD9VHq.png)

- 可输出**日志文件**，得知运行失败原因
- 单元测试覆盖至少 85% 的代码

<br>

## 使用前提

- 疫情防控通：该脚本的工作方式为：爬取您上一次上报的信息，然后自动上报同样的信息。因此，使用前，您需要保证**昨天**~~_（格林威治时间）_~~（北京时间）已经正确填报了信息。如果您尚未填报，需要手动填报后，从**第二天开始**才能使用本脚本。

- 晨午晚检：构造post请求，自动上报。
<br>

## 更新指引/Changelog

##### 从 6/19 日起脚本提示「要上报的数据似乎是破损的，可能网页已经改版」

- 从 2020/6/19 日起，随着疫情发展，北邮的「疫情防控通」更新了要填报的选项。请您**更新脚本，并至少自己填报一次**，从**下一次起再使用脚本**来自动填报。

#### 9/1提示要晨午晚检，晨检填报疫情防控通，午晚检填报晨午晚检
- 运行main2.py就可以了，具体使用和疫情防控通脚本的使用一致。 



##### 脚本提示「成功……定位信息不能为空」

事实上脚本运行失败了。新版本已修复此问题，更新即可。希望您能开启 STOP_WHEN_SICK 功能。



##### 脚本提示「您可能昨天或今天去了别的地方，……，请您今天手动提交」

- 在 2020 年 3 月 7 日的更新之后，您如果一更新就运行，会发现脚本出现如下错误：

> · 您可能昨天或今天去了别的地方，导致位置有变化；现在提交将导致数据异常，请您今天手动提交

- 如果您并没有去过外地，那么这是因为脚本之前的实现有问题：它把您的省份、地点等信息覆盖掉了。**本次更新已经修复此问题**。请您今天手动填报，从明天（或后天）开始再使用脚本。如果您所在的单位不关心您的数据，也可以关掉 STOP_WHEN_SICK 功能。

<br>

## 脚本依赖

- Python 3.6 或以上
- requests 库

<br>

## 脚本部署

本节以云服务器、AWS Lambda、GCP Cloud Function 为例阐述了部署的基本步骤，但本脚本也可以部署在其它的云函数平台上。欲知详情，请参考您的部署目标的文档。

#### 注意事项

- 如果您要自动运行本脚本，建议您于**每天上午 7 点的某分钟** 运行；在 0 点运行可能会失败。

#### 部署在云服务器上

> ⚠ 注意：Anaconda 用户可能会发现自己无法正常运行脚本。因此，若您遇到了问题，请您尝试以下链接中的方法：https://stackoverflow.com/questions/54135206/requests-caused-by-sslerrorcant-connect-to-https-url-because-the-ssl-module 。原始 Python 用户无此问题。

1. 通过 `git clone` 或 GitHub 的「下载 zip 文件」功能，将本仓库下载到您的电脑上。

2. 安装 Python 3.6 或以上版本。
   
3. `cd` 到脚本目录，通过 pip 安装依赖项：`pip install -r requirements.txt`。

4. 根据下方的「脚本配置与运行」一栏，配置脚本参数。

    

**注：** 如果您需要让该脚本定期自动运行：

1. Linux/macOS 用户可以配置 cron 等工具。参考教程：
   1. https://www.ibm.com/developerworks/cn/education/aix/au-usingcron/index.html
   2. https://crontab.guru/
2. Windows 用户可以使用系统的「任务计划」功能。

#### 部署在 AWS Lambda 上

由于 AWS Lambda 不会自动下载依赖项，因此需要您手动下载依赖项并打包上传。

1. 在 Linux 下配置 Python 3.6 虚拟环境，在虚拟环境中安装 requests。
2. 将虚拟环境下的 `site-packages` 文件夹中的内容，拷贝到与该脚本同一目录下。
3. 在 AWS Lambda 中新建一个函数：
   1. 按照下方「脚本配置与运行」一节的说明，配置环境变量。
   2. 将所有文件上传。
      1. 除 `site-packages` 文件夹的内容以外，其它非 `.py` 文件都可以忽略。
   3. 将要执行的文件设为 main.py，要执行的函数设为 main。

**注：** 您可以通过 AWS CloudWatch 来自动执行该脚本。

#### 部署在 GCP Cloud Function 上

GCP 支持通过 `requirements.txt` 自动下载依赖项，因此将所有文件（包括 `requirements.txt`） 打包上传即可。您需要：

1. 在 Cloud Function 中创建新函数。
   1. 按照下方「脚本配置与运行」一节的说明，配置环境变量。
   2. 打包上传本仓库所有文件。
      1. 您可以在 Linux 下（或 WSL 下）使用 gcp-zip.sh 脚本一键打包。
      2. 手动打包时，除 `requirements.txt` 以外，其它非 `.py` 文件都可以忽略。
   3. 将要执行的函数设为 main。

**注：** 建议您将该云函数的触发器设为 Cloud Pub/Sub 触发器，然后可以通过 GCP Cloud Scheduler 来自动执行该函数。

<br>

## 脚本配置与运行

该脚本需要配置北邮帐号等信息才能正确运行。

您可以通过**环境变量、命令行参数、修改代码**等方式来提供配置，请根据您部署的目标平台来决定使用哪种方式。

需要设置的参数如下：

| 环境变量          | 命令行参数          | 说明                                                         |
| :---------------- | ------------------- | :----------------------------------------------------------- |
| BUPT_SSO_USER     | --bupt-sso-user     | 您登录[北邮门户（https://my.bupt.edu.cn/）](https://my.bupt.edu.cn/)时使用的用户名，通常是您的学工号 |
| BUPT_SSO_PASS     | --bupt-sso-pass     | 您登录[北邮门户（https://my.bupt.edu.cn/）](https://my.bupt.edu.cn/)时使用的密码 |
| TG_BOT_TOKEN      | --tg-bot-token      | （可选）如果您需要把执行结果通过 Telegram 机器人告知，请将此变量设为您的 Telegram 机器人的 API Token |
| TG_CHAT_ID        | --tg-chat-id        | （可选）如果您需要把执行结果通过 Telegram 机器人告知，请将此变量设为您自己的用户 id |
| BNR_LOG_PATH      | --bnr-log-path      | （可选）日志文件存放的路径，未设置则不输出日志文件。（注意日志中可能有敏感信息） |
| STOP_WHEN_SICK    | --stop-when-sick    | （可选）当检测到您上报的数据表明您为疑似病患时（如体温>=37°C、接触过确诊人群等），若您开启了此选项，将停止自动上报，以防止您连续多日上报异常数据。 |
| SERVER_CHAN_SCKEY | --server-chan-sckey | （可选）如果您需要把执行结果通过 Server 酱推送到微信，请设为 Server 酱为您提供的 SCKEY。 |

**注：** 优先级为：命令行参数 > 环境变量 > 代码中的默认值。其中前者覆盖后者。

#### 运行示例

假设您登录北邮门户的账户和密码是：

- **用户名：** 2020114514
- **密码：** 114514

#### 设置环境变量

您使用 Linux 时，可以通过如下 bash 命令，设置环境变量并运行脚本：

```bash
export BUPT_SSO_USER=2020114514
export BUPT_SSO_PASS=114514
//填报疫情防控通
python3 main.py
//填报晨午晚检
python3 main2.py
```

如果您需要使用**疑似病患数据停止上报**（STOP_WHEN_SICK）功能，则只需要将该环境变量设为任意非空字符串（如：1、true）即可。

**注：** 

- 在 Windows 上，您使用的命令可能是 `python` 而不是 `python3`。您可以使用系统自带的「编辑环境变量」工具，也可以在使用 `cmd` 和 PowerShell 时设置环境变量。其中，`cmd` 和 PowerShell 的环境变量的语法各不相同，请自行研究。
- 各配置所对应的环境变量可查看上表。

#### 使用命令行参数

如果您认为设置环境变量，会让自己的密码有泄露风险，那么您可以使用环境变量提供用户名，同时又通过命令行参数来提供密码：

```bash
export BUPT_SSO_USER=2020114514
python3 main.py --bupt-sso-pass=114514
```

如果您需要使用**疑似病患数据停止上报**（STOP_WHEN_SICK）功能，那么在命令行参数使用时不需要加参数：

```bash
export BUPT_SSO_USER=2020114514
python3 main.py --bupt-sso-pass=114514 --stop-when-sick
```

如果您觉得设置环境变量太麻烦，也可以全部使用命令行参数。

**注：** 各配置所对应的命令行参数可查看上表，也可以运行命令 `python main.py --help` 查看。

#### 修改代码（不推荐）

若您部署脚本的目标平台既不提供环境变量功能，也不允许设置命令行参数，那么您可以通过修改代码的方式提供配置。找到 CONFIG_SCHEMA 变量，给对应配置的 default 属性填入您的值即可。

<br>

## 将运行结果推送到微信上

本脚本支持使用「[Server 酱](https://sc.ftqq.com/3.version)」将运行结果通过微信推送到手机上。

您只需要根据[官网上的介绍](https://sc.ftqq.com/3.version)，在「Server 酱」官网登录并绑定微信后，将网站提供的 SCKEY 作为参数传入即可：

```bash
export BUPT_SSO_USER=2020114514
python3 main.py --bupt-sso-pass=114514 --server-chan-sckey=SCUxxxxxxxxxxxxxxxx
```

<br>

## 配置代理以连接 Telegram 服务器

如果您在国内使用该脚本，您可能需要配置代理才能使用 Telegram 机器人通知功能。

本脚本所使用的 requests 库支持 HTTP 代理。您可以通过 Shadowsocks 工具开启 HTTP 代理后，将 HTTP_PROXY 和 HTTPS_PROXY 环境变量设为 `http://<代理 IP 地址>:<代理端口号>`。示例如下：

```bash
export HTTP_PROXY=http://127.0.0.1:1080
export HTTPS_PROXY=http://127.0.0.1:1080
```

<br>

## 测试与类型检查

当您修改代码后，您可以运行单元测试或类型检查来检测代码正确性。

#### 运行测试

在根目录运行命令 `python3 -m unittest` 即可。（Windows 下您可能需要 `python` 命令）

#### 运行类型检查

首先，您需要安装依赖包：

- 前往仓库内的 .github 目录；
- 根据 requirements-ci.txt 安装依赖：`pip install -r requirements-ci.txt`
- 运行命令：`mypy main.py`

**注：** 本项目的 GitHub Actions 运行 mypy 时指定了更严格的规则。可以阅读 .github 目录下的相关文件来了解详情。

<br>

## 版权

使用 MIT 协议发布，著作权由代码的贡献者所有。

