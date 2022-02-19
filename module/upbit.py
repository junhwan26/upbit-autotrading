import time
import logging
import requests
import jwt
import uuid
import hashlib

from urllib.parse import urlencode
from decimal import Decimal

import config

access_key = config.access_key
secret_key = config.secret_key
server_url = config.server_url


# -----------------------------------------------------------------------------
# - Name : sellcoin_mp
# - Desc : 시장가 매도
# - Input
#   1) target_item : 대상종목
# - Output
#   1) rtn_data : 매도결과
# -----------------------------------------------------------------------------
# 시장가 매도
def sellcoin_mp(target_item):
    try:

        # 잔고 조회
        cur_balance = get_balance(target_item)

        query = {
            'market': target_item,
            'side': 'ask',
            'volume': cur_balance,
            'ord_type': 'market',
        }

        query_string = urlencode(query).encode()

        m = hashlib.sha512()
        m.update(query_string)
        query_hash = m.hexdigest()

        payload = {
            'access_key': access_key,
            'nonce': str(uuid.uuid4()),
            'query_hash': query_hash,
            'query_hash_alg': 'SHA512',
        }

        jwt_token = jwt.encode(payload, secret_key)
        authorize_token = 'Bearer {}'.format(jwt_token)
        headers = {"Authorization": authorize_token}

        res = send_request("POST", server_url + "/v1/orders", query, headers)
        rtn_data = res.json()

        logging.info("")
        logging.info("----------------------------------------------")
        logging.info("시장가 매도 완료!")
        logging.info(rtn_data)
        logging.info("----------------------------------------------")

        return rtn_data

    # ----------------------------------------
    # Exception Raise
    # ----------------------------------------
    except Exception:
        raise


def buycoin_mp(target_item, buy_amount):
    try:

        query = {
            'market': target_item,
            'side': 'bid',
            'price': buy_amount,
            'ord_type': 'price',
        }

        query_string = urlencode(query).encode()

        m = hashlib.sha512()
        m.update(query_string)
        query_hash = m.hexdigest()

        payload = {
            'access_key': access_key,
            'nonce': str(uuid.uuid4()),
            'query_hash': query_hash,
            'query_hash_alg': 'SHA512',
        }

        jwt_token = jwt.encode(payload, secret_key)
        authorize_token = 'Bearer {}'.format(jwt_token)
        headers = {"Authorization": authorize_token}

        res = send_request("POST", server_url + "/v1/orders", query, headers)
        rtn_data = res.json()

        logging.info("")
        logging.info("----------------------------------------------")
        logging.info("시장가 매수 완료!")
        logging.info(rtn_data)
        logging.info("----------------------------------------------")

        return rtn_data

    # ----------------------------------------
    # Exception Raise
    # ----------------------------------------
    except Exception:
        raise


# -----------------------------------------------------------------------------
# - Name : get_balance
# - Desc : 주문 가능 잔고 조회
# - Input
#   1) target_item : 대상 종목
# - Output
#   2) rtn_balance : 주문 가능 잔고
# -----------------------------------------------------------------------------
def get_balance(target_item):
    try:

        # 주문 가능 잔고 리턴용
        rtn_balance = 0

        # 최대 재시도 횟수
        max_cnt = 0

        payload = {
            'access_key': access_key,
            'nonce': str(uuid.uuid4()),
        }

        jwt_token = jwt.encode(payload, secret_key)
        authorize_token = 'Bearer {}'.format(jwt_token)
        headers = {"Authorization": authorize_token}

        # 잔고가 조회 될 때까지 반복
        while True:

            # 조회 회수 증가
            max_cnt = max_cnt + 1

            res = send_request("GET", server_url + "/v1/accounts", "", headers)
            my_asset = res.json()

            # 해당 종목에 대한 잔고 조회
            # 잔고는 마켓에 상관 없이 전체 잔고가 조회됨
            #print(my_asset)
            for asset_for in my_asset:
                #print(asset_for)
                if asset_for['currency'] == target_item.split('-')[1]:
                    rtn_balance = asset_for['balance']

            # 잔고가 0 이상일 때까지 반복
            if Decimal(str(rtn_balance)) > Decimal(str(0)):
                break

            # 최대 100회 수행
            if max_cnt > 100:
                break

            logging.info("[주문 가능 잔고 리턴용] 요청 재처리중...")

        return rtn_balance

    # ----------------------------------------
    # Exception Raise
    # ----------------------------------------
    except Exception:
        raise


# -----------------------------------------------------------------------------
# - Name : get_items
# - Desc : 전체 종목 리스트 조회
# - Input
#   1) market : 대상 마켓(콤마 구분자:KRW,BTC,USDT)
#   2) except_item : 제외 종목(콤마 구분자:BTC,ETH)
# - Output
#   1) 전체 리스트 : 리스트
# -----------------------------------------------------------------------------
def get_items(market, except_item):
    try:

        # 조회 결과 리턴용
        rtn_list = []

        # 마켓 데이터
        markets = market.split(',')

        # 제외 데이터
        except_items = except_item.split(',')

        url = server_url + "/v1/market/all"
        querystring = {"isDetails": "false"}
        response = send_request("GET", url, querystring, "")
        data = response.json()

        # 조회 마켓만 추출
        for data_for in data:
            for market_for in markets:
                if data_for['market'].split('-')[0] == market_for:
                    rtn_list.append(data_for)

        # 제외 종목 제거
        for rtnlist_for in rtn_list[:]:
            for exceptItemFor in except_items:
                for marketFor in markets:
                    if rtnlist_for['market'] == marketFor + '-' + exceptItemFor:
                        rtn_list.remove(rtnlist_for)

        return rtn_list

    # ----------------------------------------
    # Exception Raise
    # ----------------------------------------
    except Exception:
        raise


def set_loglevel(level):
    try:

        # ---------------------------------------------------------------------
        # 로그 레벨 : DEBUG
        # ---------------------------------------------------------------------
        if level.upper() == "D":
            logging.basicConfig(
                format='[%(asctime)s][%(levelname)s][%(filename)s:%(lineno)d]:%(message)s',
                datefmt='%Y/%m/%d %I:%M:%S %p',
                level=logging.DEBUG
            )
        # ---------------------------------------------------------------------
        # 로그 레벨 : ERROR
        # ---------------------------------------------------------------------
        elif level.upper() == "E":
            logging.basicConfig(
                format='[%(asctime)s][%(levelname)s][%(filename)s:%(lineno)d]:%(message)s',
                datefmt='%Y/%m/%d %I:%M:%S %p',
                level=logging.ERROR
            )
        # ---------------------------------------------------------------------
        # 로그 레벨 : INFO
        # ---------------------------------------------------------------------
        else:
            # -----------------------------------------------------------------------------
            # 로깅 설정
            # 로그 레벨(DEBUG, INFO, WARNING, ERROR, CRITICAL)
            # -----------------------------------------------------------------------------
            logging.basicConfig(
                format='[%(asctime)s][%(levelname)s][%(filename)s:%(lineno)d]:%(message)s',
                datefmt='%Y/%m/%d %I:%M:%S %p',
                level=logging.INFO
            )

    # ----------------------------------------
    # Exception Raise
    # ----------------------------------------
    except Exception:
        raise


# -----------------------------------------------------------------------------
# - Name : send_request
# - Desc : request 처리
# - Input
#   1) req_type : 요청 타입
#   2) reqUrl : 요청 URL
#   3) reqParam : 요청 parameter
#   4) reqHeader : 요청 헤더
# - Output
#   4) response : 응답 데이터
# -----------------------------------------------------------------------------
def send_request(req_type, req_url, req_param, req_header):
    try:
        # 요청 가능 횟수 확보를 위해 기다리는 시간(초)
        err_sleep_time = 1

        # 요청에 대한 응답을 받을 때까지 반복 수행
        while True:

            # 요청 처리
            response = requests.request(req_type, req_url, params=req_param, headers=req_header)

            # 요청 가능 횟수 추출
            if 'Remaining-Req' in response.headers:

                header_info = response.headers['Remaining-Req']
                start_idx = header_info.find("sec=")
                end_idx = len(header_info)
                remain_sec = header_info[int(start_idx):int(end_idx)].replace('sec=', '')
            else:
                logging.error("헤더 정보 이상")
                logging.error(response.headers)
                break

            # 요청 가능 횟수가 4개 미만이면 요청 가능 횟수 확보를 위해 일정 시간 대기
            if int(remain_sec) < 4:
                logging.debug("요청 가능 횟수 한도 도달! 남은 횟수:" + str(remain_sec))
                time.sleep(err_sleep_time)

            # 정상 응답
            if response.status_code == 200 or response.status_code == 201:
                break
            # 요청 가능 횟수 초과인 경우
            elif response.status_code == 429:
                logging.error("요청 가능 횟수 초과!:" + str(response.status_code))
                time.sleep(err_sleep_time)
            # 그 외 오류
            else:
                logging.error("기타 에러:" + str(response.status_code))
                logging.error(response.status_code)
                break

            # 요청 가능 횟수 초과 에러 발생 시에는 다시 요청
            logging.info("[restRequest] 요청 재처리중...")

        return response

    # ----------------------------------------
    # Exception Raise
    # ----------------------------------------
    except Exception:
        raise
