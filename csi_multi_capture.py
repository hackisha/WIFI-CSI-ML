#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
필수:
  pip3 install pcap dpkt pandas numpy keyboard
"""

import os
import sys
import time
import shutil
import warnings
from datetime import datetime
from typing import Optional, Set, Dict

import pcap
import dpkt
import pandas as pd
import numpy as np

# keyboard 모듈이 없으면 's' 중지 기능만 비활성
try:
    import keyboard
    KEYBOARD_AVAILABLE = True
except Exception:
    KEYBOARD_AVAILABLE = False

# ===== pandas FutureWarning 숨김 (빈 DF concat 관련) =====
warnings.simplefilter("ignore", FutureWarning)

# ===== 사용자 설정(cfg.py) =====
# cfg.EXTRACTOR_CONFIG['bandwidth'] (MHz) 를 사용합니다.
import cfg

# ===== 기본 경로/상수 =====
OUTPUT_ROOT = '../data'
os.makedirs(OUTPUT_ROOT, exist_ok=True)

BANDWIDTH_MHZ = cfg.EXTRACTOR_CONFIG.get('bandwidth', 20)  # 20 or 40
NSUB = int(BANDWIDTH_MHZ * 3.2)  # 서브캐리어 수(기존 규칙: MHz * 3.2)
UDP_PORT = 5500

# NIC은 고정
NIC_NAME = 'wlan0'

# =====================================================================
# 터미널 컬러/배너 유틸
# =====================================================================

def _supports_color() -> bool:
    try:
        return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"
    except Exception:
        return False

USE_COLOR = _supports_color()

def color(txt: str, fg: Optional[str] = None, bg: Optional[str] = None, bold: bool = True) -> str:
    if not USE_COLOR:
        return txt
    codes = []
    if bold:
        codes.append('1')
    fg_map = {
        'black':'30','red':'31','green':'32','yellow':'33','blue':'34',
        'magenta':'35','cyan':'36','white':'37','bright_red':'91',
        'bright_green':'92','bright_yellow':'93','bright_blue':'94',
        'bright_magenta':'95','bright_cyan':'96','bright_white':'97'
    }
    bg_map = {
        'black':'40','red':'41','green':'42','yellow':'43','blue':'44',
        'magenta':'45','cyan':'46','white':'47','bright_red':'101',
        'bright_green':'102','bright_yellow':'103','bright_blue':'104',
        'bright_magenta':'105','bright_cyan':'106','bright_white':'107'
    }
    if fg and fg in fg_map: codes.append(fg_map[fg])
    if bg and bg in bg_map: codes.append(bg_map[bg])
    if codes:
        return f"\033[{';'.join(codes)}m{txt}\033[0m"
    return txt

def term_width(default: int = 72) -> int:
    try:
        w = shutil.get_terminal_size((default, 20)).columns
        return max(50, min(w, 120))
    except Exception:
        return default

def banner_box(lines, fg='bright_white', bg=None, border_char='═'):
    w = term_width()
    border = border_char * w
    print(color(border, fg=fg, bg=bg))
    for line in lines:
        s = f"  {line}"
        # 우측 패딩
        if len(s) < w:
            s = s + ' ' * (w - len(s))
        print(color(s, fg=fg, bg=bg))
    print(color(border, fg=fg, bg=bg))

def banner_ready(delay_sec: int):
    lines = [
        f"준비 시간 {delay_sec}초 - 자세를 잡고 대기하세요",
        "(이 구간은 저장하지 않습니다)"
    ]
    banner_box(lines, fg='bright_cyan')

def banner_baseline(sec: float):
    lines = [
        f"베이스라인 측정 시작: {sec:.1f}초",
        "지금은 '정지' 상태입니다. 움직이지 마세요."
    ]
    banner_box(lines, fg='bright_green')

def banner_baseline_done():
    banner_box(["베이스라인 완료"], fg='bright_green')

def banner_action(act: str, sec: float):
    # 빨간 배경 + 흰색 글자(눈에 띄게)
    lines = [
        f"★★★ 동작 수행 시작: '{act}' — {sec:.1f}초 ★★★",
        "지금 동작을 수행하세요!"
    ]
    banner_box(lines, fg='bright_white', bg='red', border_char='█')

def banner_action_done():
    banner_box(["동작 측정 완료"], fg='bright_white', bg='bright_red', border_char='█')

def banner_capture(idx: int):
    banner_box([f"캡처 #{idx} 시작"], fg='bright_yellow')

def banner_save():
    banner_box(["저장 중..."], fg='bright_yellow')

def info_line(msg: str):
    print(color(msg, fg='bright_white', bold=False))

def ok_line(msg: str):
    print(color(msg, fg='bright_green'))

def warn_line(msg: str):
    print(color(msg, fg='bright_yellow'))

def err_line(msg: str):
    print(color(msg, fg='bright_red'))

# =====================================================================
# 유틸
# =====================================================================

def normalize_mac_hex(s: str) -> str:
    """콜론/대문자 섞여 들어와도 내부는 'aabbccddeeff' 형태로 통일."""
    return s.replace(":", "").replace("-", "").strip().lower()

def unique_tail(mac_hex: str, n: int = 4) -> str:
    return mac_hex[-n:]

def session_dir() -> str:
    sd = os.path.join(OUTPUT_ROOT, datetime.now().strftime("session_%Y%m%d_%H%M%S"))
    os.makedirs(sd, exist_ok=True)
    return sd

def truncate_bin_idx(ts_sec: float, bin_ms: float) -> int:
    """ms 단위 bin index 계산(다운샘플링용)."""
    return int((ts_sec * 1000.0) / bin_ms)

def is_stop_pressed() -> bool:
    if not KEYBOARD_AVAILABLE:
        return False
    try:
        return keyboard.is_pressed('s')
    except Exception:
        return False

def countdown(sec: int):
    for s in range(int(sec), 0, -1):
        info_line(f"  - {s}초 남음")
        time.sleep(1)

def make_empty_csi_df(nsub: int) -> pd.DataFrame:
    """컬럼 dtype을 명시한 '빈' CSI DataFrame 생성 (concat 경고 방지)"""
    cols = {
        'mac': pd.Series(dtype='object'),
        'time': pd.Series(dtype='float64'),
    }
    for i in range(nsub):
        cols[f'_{i}'] = pd.Series(dtype='complex128')
    return pd.DataFrame(cols)

# =====================================================================
# 핵심: CSI 캡처
# =====================================================================

def capture_csi(nicname: str,
                duration_sec: float,
                allow_macs: Optional[Set[str]] = None,
                per_mac_bin_ms: Optional[float] = 10.0) -> Dict[str, pd.DataFrame]:
    """
    allow_macs: {'aabbccddeeff', ...} 허용 MAC만 수집(None이면 모두)
    per_mac_bin_ms: MAC별 다운샘플 bin(ms). None/0 이면 다운샘플 비활성
    반환: { mac_hex: DataFrame(columns=['mac','time','_0'..]) }
    """
    sniffer = pcap.pcap(name=nicname, promisc=True, immediate=True, timeout_ms=10)
    sniffer.setfilter(f'udp and port {UDP_PORT}')

    mac_dict: Dict[str, pd.DataFrame] = {}
    last_bin_by_mac: Dict[str, int] = {}

    t0 = time.time()
    for ts, pkt in sniffer:
        if (time.time() - t0) > duration_sec or is_stop_pressed():
            break
        try:
            eth = dpkt.ethernet.Ethernet(pkt)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):      # IPv4만 처리
                continue
            udp = ip.data
            if not isinstance(udp, dpkt.udp.UDP):   # UDP만
                continue

            payload = bytes(udp.data)
            if len(payload) < 18:
                continue

            # 기존 포맷: [4:10] = 6B MAC 식별 / [18:] = IQ(int16) interleaved
            mac_hex = payload[4:10].hex()
            if allow_macs is not None and mac_hex not in allow_macs:
                continue

            # (선택) MAC별 다운샘플: 같은 MAC에서 같은 bin이면 스킵
            if per_mac_bin_ms and per_mac_bin_ms > 0:
                bin_idx = truncate_bin_idx(ts, per_mac_bin_ms)
                if last_bin_by_mac.get(mac_hex) == bin_idx:
                    continue
                last_bin_by_mac[mac_hex] = bin_idx

            raw = payload[18:]
            need = NSUB * 2  # I,Q interleaved 개수
            if len(raw) < need * 2:
                continue

            csi_np = np.frombuffer(raw, dtype=np.int16, count=need).reshape(1, need)
            csi_cmplx = np.fft.fftshift(csi_np[:, ::2] + 1.j * csi_np[:, 1::2], axes=(1,))

            # mac별 빈 DF 생성(명시 dtype)
            if mac_hex not in mac_dict:
                mac_dict[mac_hex] = make_empty_csi_df(NSUB)

            # 한 줄 DF (스키마 맞추기)
            df_row = pd.DataFrame(csi_cmplx)
            df_row.rename(columns={i: f'_{i}' for i in range(NSUB)}, inplace=True)
            df_row.insert(0, 'time', float(ts))      # float64
            df_row.insert(0, 'mac', str(mac_hex))    # object
            df_row = df_row[mac_dict[mac_hex].columns]  # 컬럼 순서 정렬

            mac_dict[mac_hex] = pd.concat([mac_dict[mac_hex], df_row], ignore_index=True)

        except Exception:
            # 손상 프레임 등은 무시
            pass

    return mac_dict

# =====================================================================
# 저장
# =====================================================================

def save_csv(df: pd.DataFrame, path: str):
    df.to_csv(path, index=False)
    ok_line(f"[저장] {path} (행 {len(df):,}개)")

# =====================================================================
# 모드: 저장 전용
# =====================================================================

def mode_save_only(nicname: str):
    print()
    banner_box(["저장 전용 모드"], fg='bright_yellow')

    base = input("파일 이름 접두어(예: test): ").strip() or "test"

    # 시작 번호(재개 용도)
    start_idx = int(input("시작 번호(기본 1): ").strip() or "1")

    # 반복 횟수('-' 입력 시 무한 반복)
    rpt_text = input("반복 횟수('-' 입력 시 무한 반복): ").strip()
    repeat = -1 if rpt_text == '-' else int(rpt_text or "1")

    duration = float(input("캡처 시간(초): ").strip())
    delay = int(input("캡처 전 대기(초): ").strip() or "0")

    # MAC 필터(3대만 지정 추천)
    use_filter = input("특정 MAC만 수집할까요? (y/n): ").strip().lower() == 'y'
    allow = None
    if use_filter:
        print("MAC 목록 입력(콤마 구분, 콜론 있어도 됨):")
        ms = input("예) e0:5a:1b:a0:e7:0c, ec:e3:34:21:a5:20, 38:18:2b:2e:ef:40\n> ").strip()
        allow = {normalize_mac_hex(m) for m in ms.split(',') if m.strip()}

    # MAC별 다운샘플 bin(ms). 빈 입력 시 10, 0 입력 시 끔
    bin_text = input("MAC별 다운샘플(bin ms, 기본 10, 0=끄기): ").strip()
    per_mac_bin_ms: Optional[float] = None if bin_text == "" else float(bin_text)
    if per_mac_bin_ms == 0:
        per_mac_bin_ms = None

    idx = start_idx
    while repeat == -1 or idx < start_idx + repeat:
        if is_stop_pressed():
            warn_line("사용자 중지(s). 종료합니다.")
            break

        banner_capture(idx)

        if delay > 0:
            banner_ready(delay)
            countdown(delay)

        info_line("- 캡처 진행 중...")
        mac_dict = capture_csi(nicname, duration, allow_macs=allow, per_mac_bin_ms=per_mac_bin_ms)

        banner_save()
        now_tag = datetime.now().strftime("%H%M%S")
        if not mac_dict:
            warn_line("[경고] 수집된 프레임이 없습니다.")
        else:
            info_line("[요약] MAC별 행 수:")
            for mac, df in mac_dict.items():
                info_line(f"  - {mac} : {len(df):,}행")
            for mac, df in mac_dict.items():
                fname = f"{base}_{idx}_mac{unique_tail(mac)}_{now_tag}.csv"
                save_csv(df, os.path.join(OUTPUT_ROOT, fname))

        idx += 1

# =====================================================================
# 모드: 가이드(무음, 콘솔 안내만)
# =====================================================================

def mode_guided(nicname: str):
    """
    콘솔 안내(무음). 세션 폴더에 저장.
    좌표/방향/행동/반복/시작번호 지정 가능.
    """
    print()
    banner_box(["가이드 모드(무음)"], fg='bright_yellow')
    sess = session_dir()
    ok_line(f"- 세션 폴더: {sess}")

    # 시작 번호(재개 용도)
    start_idx = int(input("시작 번호(기본 1): ").strip() or "1")

    # Diamond-9 좌표(csv 없으면 기본 좌표 사용)
    diamond_csv = 'diamond9_2x2m.csv'
    grid = None
    if os.path.isfile(diamond_csv):
        try:
            df = pd.read_csv(diamond_csv)
            grid = {int(r.pos_id):(float(r.x_m), float(r.y_m)) for _, r in df.iterrows()}
        except Exception:
            grid = None
    if not grid:
        grid = {
            0:(0.0,0.0), 1:(2.0,0.0), 2:(0.0,2.0), 3:(2.0,2.0),
            4:(1.0,0.0), 5:(0.0,1.0), 6:(2.0,1.0), 7:(1.0,2.0), 8:(1.0,1.0)
        }

    pos_text = input("포지션 ID들(콤마, 기본: 0..8 모두): ").strip()
    pos_ids = [int(x) for x in pos_text.split(',')] if pos_text else list(sorted(grid.keys()))

    ori_text = input("방향(deg, 콤마, 기본: 0,90): ").strip()
    orientations = [int(x) for x in ori_text.split(',')] if ori_text else [0, 90]

    actions_text = input("행동들(콤마, 기본: idle,sit_stand,inplace_walk,raise_one_arm): ").strip()
    actions = actions_text.split(',') if actions_text else ['idle','sit_stand','inplace_walk','raise_one_arm']

    repeats = int(input("반복 횟수(기본 3): ").strip() or "3")

    # 타이밍
    baseline_sec = float(input("베이스라인 시간(초, 기본 0.5): ").strip() or "0.5")
    action_sec   = float(input("동작 시간(초, 기본 1.0): ").strip() or "1.0")
    delay_before = int(input("클립 시작 전 대기(초, 기본 2): ").strip() or "2")

    # MAC 필터
    ms = input("타깃 MAC들(콤마, 콜론 허용, 비우면 전체): ").strip()
    allow: Optional[Set[str]] = {normalize_mac_hex(m) for m in ms.split(',') if m.strip()} if ms else None

    # MAC별 다운샘플 bin(ms)
    bin_text = input("MAC별 다운샘플(bin ms, 기본 10, 0=끄기): ").strip()
    per_mac_bin_ms: Optional[float] = None if bin_text == "" else float(bin_text)
    if per_mac_bin_ms == 0:
        per_mac_bin_ms = None

    total = len(pos_ids) * len(orientations) * len(actions) * repeats
    prog = 0
    clip_idx = start_idx

    ok_line(f"\n총 {total} 클립 예정. 's' 키로 중단 가능, 또는 Ctrl+C.")

    for pos_id in pos_ids:
        x, y = grid.get(pos_id, (None, None))
        for ori in orientations:
            for act in actions:
                for rep in range(1, repeats + 1):
                    prog += 1
                    title = f"[{prog}/{total}] pos{pos_id}({x:.1f},{y:.1f}) ori{ori} act:{act} rep:{rep} → 클립 #{clip_idx}"
                    banner_box([title], fg='bright_white')

                    if is_stop_pressed():
                        warn_line("사용자 중지(s). 종료합니다.")
                        return

                    # 준비/대기 (저장 안 함)
                    banner_ready(delay_before)
                    countdown(delay_before)

                    # 베이스라인 (저장)
                    banner_baseline(baseline_sec)
                    t0 = time.time()
                    mac_dict = capture_csi(nicname, baseline_sec, allow_macs=allow, per_mac_bin_ms=per_mac_bin_ms)
                    banner_baseline_done()

                    # 동작 (저장)
                    banner_action(act, action_sec)
                    more = capture_csi(nicname, action_sec, allow_macs=allow, per_mac_bin_ms=per_mac_bin_ms)
                    banner_action_done()

                    # 병합
                    for mac, df in more.items():
                        if mac in mac_dict:
                            mac_dict[mac] = pd.concat([mac_dict[mac], df], ignore_index=True)
                        else:
                            mac_dict[mac] = df

                    # 저장
                    banner_save()
                    now_tag = datetime.now().strftime("%H%M%S")
                    if not mac_dict:
                        warn_line("  · (경고) 수집된 프레임이 없습니다.")
                    else:
                        info_line("  · MAC별 행 수:")
                        for mac, df in mac_dict.items():
                            info_line(f"    - {mac} : {len(df):,}행")

                        for mac, df in mac_dict.items():
                            fname = f"pos{pos_id}_ori{ori}_{act}_rep{rep}_mac{unique_tail(mac)}_{now_tag}_clip{clip_idx}.csv"
                            path = os.path.join(sess, fname)
                            save_csv(df, path)

                    clip_idx += 1
                    if is_stop_pressed():
                        warn_line("사용자 중지(s). 종료합니다.")
                        return

    ok_line("\n모든 클립 저장이 완료되었습니다.")

# =====================================================================
# 모드: MAC 탐색(간단 확인)
# =====================================================================

def mode_discover(nicname: str, seconds: int = 5):
    banner_box([f"MAC 탐색: {nicname} / {seconds}초"], fg='bright_yellow')
    seen = set()
    sniffer = pcap.pcap(name=nicname, promisc=True, immediate=True, timeout_ms=50)
    sniffer.setfilter(f'udp and port {UDP_PORT}')
    t0 = time.time()
    for ts, pkt in sniffer:
        if time.time() - t0 > seconds or is_stop_pressed():
            break
        try:
            eth = dpkt.ethernet.Ethernet(pkt)
            ip = eth.data
            udp = ip.data
            payload = bytes(udp.data)
            if len(payload) >= 10:
                mac_hex = payload[4:10].hex()
                seen.add(mac_hex)
        except Exception:
            pass
    if seen:
        ok_line("[발견] 다음 MAC이 보였습니다:")
        for m in sorted(seen):
            info_line(" - " + m)
    else:
        warn_line("[발견] MAC을 찾지 못했습니다.")

# =====================================================================
# 메인
# =====================================================================

def main():
    banner_box([f"CSI 다중 수신 도구 — NIC: {NIC_NAME}"], fg='bright_white')

    print("\n모드를 선택하세요:")
    print("  1 - 저장 전용 모드")
    print("  2 - 가이드 모드(무음, 콘솔 안내)")
    print("  3 - MAC 탐색(빠른 확인)")
    mode = input("모드 번호 입력: ").strip()

    try:
        if mode == '1':
            mode_save_only(NIC_NAME)
        elif mode == '2':
            mode_guided(NIC_NAME)
        elif mode == '3':
            sec = int(input("스캔 시간(초, 기본 5): ").strip() or "5")
            mode_discover(NIC_NAME, seconds=sec)
        else:
            err_line("올바르지 않은 모드입니다.")
    except KeyboardInterrupt:
        warn_line("\n사용자 중지(Ctrl+C). 종료합니다.")

if __name__ == '__main__':
    main()
