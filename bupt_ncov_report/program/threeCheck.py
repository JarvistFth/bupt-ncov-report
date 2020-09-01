#

import json
import logging
import sys
import traceback
from typing import List, Mapping, Optional, cast

import requests

from ..constant import *
from ..notifier import *
from ..predef import *
from ..program_utils import *

logger = logging.getLogger(__name__)


class ThreeCheckProgram:
    COMMON_HEADERS = {
        'User-Agent': HEADERS.UA,
        'Accept-Language': HEADERS.ACCEPT_LANG,
    }

    # 能在多个 POST 请求中复用的 HTTP header。不含 COMMON_HEADERS，请手动将这两个常量混合
    COMMON_POST_HEADERS = {
        'Accept': HEADERS.ACCEPT_JSON,
        'Origin': HEADERS.ORIGIN_BUPTAPP,
        'X-Requested-With': HEADERS.REQUEST_WITH_XHR,
        'Content-Type': HEADERS.CONTENT_TYPE_UTF8,
    }

    def __init__(
            self, *,
            config: Mapping[str, Optional[ConfigValue]],
            program_utils: ProgramUtils,
            session: requests.Session,
            notifiers: List[INotifier],
            # askforleave=0,
            # sfzx=1

    ):
        # self.askforleave = askforleave
        # self.sfzx = sfzx
        self._prog_util = program_utils
        self._sess = session
        self._notifiers = notifiers

        self._check_config(config)

        # 初始化整个 bupt_ncov_report 模块的根 logger
        self._initialize_logger(
            logging.getLogger('bupt_ncov_report'),
            cast(Optional[str], config.get('BNR_LOG_PATH')),
        )

        self._conf: Mapping[str, Optional[ConfigValue]] = config
        self._exit_status: int = 0

    def get_exit_status(self) -> int:
        return self._exit_status

    @staticmethod
    def _check_config(config: Mapping[str, Optional[ConfigValue]]) -> None:
        """
        检查程序配置是否正确；如不正确则抛出异常。
        :return: None
        """

        # 检查 BUPT SSO 用户名、密码
        for key in ('BUPT_SSO_USER', 'BUPT_SSO_PASS'):
            if config[key] is None:
                raise ValueError(f'配置 {key} 未设置。缺少此配置，该脚本无法自动登录北邮网站。')

        # 检查 Telegram 的环境变量是否已经设置
        if (config['TG_BOT_TOKEN'] is None) != (config['TG_CHAT_ID'] is None):
            raise ValueError('TG_BOT_TOKEN 和 TG_CHAT_ID 必须同时设置，否则程序无法正确运行。')

    @staticmethod
    def _initialize_logger(logger: logging.Logger, log_file: Optional[str]) -> None:
        """
        初始化传入的 Logger 对象，
        将 INFO 以上的日志输出到屏幕，将所有日志存入文件。
        :param logger: Logger 对象
        :param log_file: 日志文件路径
        :return: None
        """
        logger.setLevel(logging.DEBUG)

        # 将日志输出到控制台
        sh = logging.StreamHandler(sys.stdout)
        sh.setLevel(logging.INFO)
        sh.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        logger.addHandler(sh)

        # 将日志输出到文件
        if log_file:
            fh = logging.FileHandler(log_file, encoding='utf-8')
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            logger.addHandler(fh)

    def do_check_report(self) -> str:
        logger.info('登录北邮 晨检晚检 上报网站')
        login_res = self._sess.post(LOGIN_API, data={
            'username': cast(str, self._conf['BUPT_SSO_USER']),
            'password': cast(str, self._conf['BUPT_SSO_PASS']),
        }, headers={
            **self.COMMON_HEADERS,
            **self.COMMON_POST_HEADERS,
            'Referer': HEADERS.REFERER_LOGIN_API,
        })
        if login_res.status_code != 200:
            logger.debug(f'登录页：\n'
                         f'status code: {login_res.status_code}\n'
                         f'url: {login_res.url}')
            raise RuntimeError('登录 API 返回的 HTTP 状态码不是 200。')

        # post_data = {'sfzx': self.sfzx, 'tw': '1', 'area': '北京市 海淀区', 'city': '北京市', 'province': '北京市',
        #              'address': '北京市海淀区北太平庄街道北京邮电大学',
        #              'geo_api_info': '{"type":"complete","info":"SUCCESS","status":1,"XDa":"jsonp_388833_","position":{"Q":39.96453,"R":116.35680000000002,"lng":116.3568,"lat":39.96453},"message":"Get ipLocation success.Get address success.","location_type":"ip","accuracy":null,"isConverted":true,"addressComponent":{"citycode":"010","adcode":"110108","businessAreas":[{"name":"北下关","id":"110108","location":{"Q":39.955976,"R":116.33873,"lng":116.33873,"lat":39.955976}},{"name":"小西天","id":"110108","location":{"Q":39.957147,"R":116.364058,"lng":116.364058,"lat":39.957147}},{"name":"西直门","id":"110102","location":{"Q":39.942856,"R":116.34666099999998,"lng":116.346661,"lat":39.942856}}],"neighborhoodType":"科教文化服务;学校;高等院校","neighborhood":"北京邮电大学","building":"","buildingType":"","street":"师大北路","streetNumber":"5号","country":"中国","province":"北京市","city":"","district":"海淀区","township":"北太平庄街道"},"formattedAddress":"北京市海淀区北太平庄街道北京邮电大学","roads":[],"crosses":[],"pois":[]}',
        #              'sfgyclq': '0', 'sfyzz': '0', 'qtqk': '', 'askforleave': self.askforleave}

        getinfo_res = self._sess.get(DAYLYGET_API, headers={
            **self.COMMON_HEADERS,
            **self.COMMON_POST_HEADERS,
            'Referer': HEADERS.REFERER_DAYLY_API
        })

        if getinfo_res.status_code != 200:
            raise RuntimeError(f'获取晨午晚检旧信息 返回的 HTTP 状态码（{getinfo_res.status_code}）不是 200。')

        content = getinfo_res.text
        post_data = json.loads(content).get('d').get('info')
        logger.info('postdata: ' + json.dumps(post_data,ensure_ascii=False))

        report_api_res = self._sess.post(
            DAILYPOST_API,
            data=post_data,
            headers={
                **self.COMMON_HEADERS,
                **self.COMMON_POST_HEADERS,
                'Referer': HEADERS.REFERER_DAYLY_API,
            },
        )
        if report_api_res.status_code != 200:
            raise RuntimeError(f'上报 API 返回的 HTTP 状态码（{report_api_res.status_code}）不是 200。')

        return report_api_res.text

    def main(self) -> str:
        """
        真正的主函数。
        该函数读取程序配置，并尝试调用工作函数；
        该函数随后获取工作函数的返回值或异常内容，通过 INotifier 发送给用户。

        :return: 通过 INotifier 发送的信息
        """
        # 运行工作函数
        logger.info('运行工作函数')
        success = True
        try:
            res = self.do_check_report()
        except:
            success = False
            res = traceback.format_exc()

        # 生成消息并打印到控制台
        if success:
            logger.info(f'成功：服务器的返回是：\n\n{res}')
        else:
            logger.info(f'失败：发生如下异常：\n\n{res}')

        # 将执行结果通过 INotifier 通知用户
        for notifier in self._notifiers:
            logger.info(f'通过「{notifier.PLATFORM_NAME}」给用户发送通知')
            try:
                notifier.notify(success=success, msg=res)
            except:
                logger.exception(f'使用「{notifier.PLATFORM_NAME}」通知失败，发生异常：')

        if not success:
            self._exit_status = 1
        return res
