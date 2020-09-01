# coding=utf-8
from bupt_ncov_report.program.threeCheck import ThreeCheckProgram

__all__ = (
    'main',
)

from typing import Dict, List, Optional, cast

import requests

from bupt_ncov_report import *
from kv_config_reader import *

# 该变量用于给每一个设置项生成文档。
# 如果您无法设置环境变量、命令行参数，可以在此处指定默认值；详情参考文档。
CONFIG_SCHEMA: Dict[str, ConfigSchemaItem] = {
    'BUPT_SSO_USER': ConfigSchemaItem(
        description='您登录北邮门户（https://my.bupt.edu.cn/）时使用的用户名，通常是您的学工号',
        for_short='北邮账号',
        default=None,
        type=str,
    ),
    'BUPT_SSO_PASS': ConfigSchemaItem(
        description='您登录北邮门户（https://my.bupt.edu.cn/）时使用的密码',
        for_short='北邮密码',
        default=None,
        type=str,
    ),
    'TG_BOT_TOKEN': ConfigSchemaItem(
        description='（可选）如果您需要把执行结果通过 Telegram 机器人告知，'
                    '请设为您的 Telegram 机器人的 API Token',
        for_short='Bot Token',
        default=None,
        type=str,
    ),
    'TG_CHAT_ID': ConfigSchemaItem(
        description='（可选）如果您需要把执行结果通过 Telegram 机器人告知，'
                    '请设为您自己的用户 id',
        for_short='用户 ID',
        default=None,
        type=str,
    ),
    'BNR_LOG_PATH': ConfigSchemaItem(
        description='（可选）日志文件存放的路径，未设置则不输出日志文件。（注意日志中可能有敏感信息）',
        for_short='路径',
        default=None,
        type=str,
    ),
    'STOP_WHEN_SICK': ConfigSchemaItem(
        description='（可选）当检测到您上报的数据表明您为疑似病患时（如体温>=37°C、接触过确诊人群等），'
                    '若您开启了此选项，将停止自动上报，以防止您连续多日上报异常数据。',
        for_short='',
        default=False,
        type=bool,
    ),
    'SERVER_CHAN_SCKEY': ConfigSchemaItem(
        description='（可选）如果您需要把执行结果通过 Server 酱推送到微信，请设为 Server 酱为您提供的 SCKEY。',
        for_short='SCKEY',
        default=None,
        type=str,
    ),
}
PROGRAM_DESC = '自动填写北邮「疫情防控通」的每日上报信息。'


def fill_config(config: Dict[str, Optional[ConfigValue]]) -> None:
    """
    往 _conf 中按照 env、cmdargs 的顺序填入配置值。
    :param config: dict 对象
    :return: None
    """

    fillers: List[IFiller] = [
        EnvFiller(),
        CmdArgsFiller(description=PROGRAM_DESC),
    ]

    for filler in fillers:
        filler.fill(config, CONFIG_SCHEMA)


def initialize_notifier(config: Dict[str, Optional[ConfigValue]]) -> List[INotifier]:
    """
    初始化 Notifier 对象，用于实现运行结果通知用户的功能。
    :param config: 通过 kv_config_reader 获取到的配置
    :return: list，元素是 INotifier 的子类
    """
    res: List[INotifier] = []

    # 检查两个 Telegram 参数是否未同时填写
    if bool(config['TG_BOT_TOKEN']) != bool(config['TG_CHAT_ID']):
        raise ValueError('TG_BOT_TOKEN 与 TG_CHAT_ID 必须同时填写。')

    # 若两个 Telegram 参数都填写了，则初始化 Telegram 通知器
    if config['TG_BOT_TOKEN'] and config['TG_CHAT_ID']:
        res.append(TelegramNotifier(
            token=cast(str, config['TG_BOT_TOKEN']),
            chat_id=cast(str, config['TG_CHAT_ID']),
            session=requests.Session(),
        ))

    # 如果填写了 SCKEY，就初始化 Server 酱通知器
    if config['SERVER_CHAN_SCKEY']:
        res.append(ServerChanNotifier(
            sckey=cast(str, config['SERVER_CHAN_SCKEY']),
            sess=requests.Session(),
        ))

    return res


def main(*wtf: object, **kwwtf: object) -> object:
    """
    入口函数。该函数用于在允许直接运行的同时，兼容 GCP Cloud Function/AWS Lambda 等云函数平台。
    :return: 由检测到的平台决定
    """

    config: Dict[str, Optional[ConfigValue]] = initialize_config(CONFIG_SCHEMA)
    fill_config(config)

    # 搭积木；手动建立各个类的实例，并注入依赖
    notifiers = initialize_notifier(config)
    pure_util = PureUtils()
    # program = Program(
    #     config=config,
    #     program_utils=ProgramUtils(pure_util),
    #     session=requests.Session(),
    #     notifiers=notifiers,
    # )
    threeCheckProgram = ThreeCheckProgram(config=config,
                                          program_utils=ProgramUtils(pure_util),
                                          session=requests.Session(),
                                          notifiers=notifiers,
                                          )


    # 运行程序
    threeCheckProgram.main()
    return threeCheckProgram.get_exit_status()


if __name__ == '__main__':
    status_code = main()
    exit(status_code)
