"""命令行参数解析。"""
import argparse


def get_parse():
    parser = argparse.ArgumentParser(
        description='Ingram-Pro：网络摄像头漏洞扫描器（增强版）'
    )
    parser.add_argument('-i', '--in_file',  type=str, required=True,
                        help='目标文件，或单个 IP / CIDR / 范围')
    parser.add_argument('-o', '--out_dir',  type=str, required=True,
                        help='结果保存目录')
    parser.add_argument('-p', '--ports',    type=int, nargs='+', default=None,
                        help='要扫描的端口（覆盖默认列表）')
    parser.add_argument('-t', '--th_num',   type=int, default=150,
                        help='并发数（默认 150）')
    parser.add_argument('-T', '--timeout',  type=int, default=3,
                        help='请求超时秒数（默认 3）')
    parser.add_argument('-D', '--disable_snapshot', action='store_true',
                        help='关闭快照抓取')
    parser.add_argument('--no-resume', dest='no_resume', action='store_true',
                        help='忽略上次进度，从头开始')
    parser.add_argument('--debug', action='store_true',
                        help='输出调试日志')
    return parser.parse_args()
