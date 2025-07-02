#!/usr/bin/env python3
"""
NetSentinel + Cohere integration (rate limit aware)
- Local statistical labelling
- Cohere (free API key) opinion (max 10 calls per minute)
"""

import csv
import os
import statistics
import time
from collections import defaultdict

import matplotlib
import pandas as pd
from dotenv import load_dotenv
from scapy.all import sniff

# Mac uyumlu çizim motoru
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt

# Anahtarları yükle ve Cohere başlat
load_dotenv()
import cohere

co = cohere.Client(os.getenv("COHERE_API_KEY"))


def cohere_assess_packet(size: int) -> str:
    """
    Cohere API'sinden paketin anormal olup olmadığını öğren.
    Yanıt sadece '0' veya '1' olmalı, gerekiyorsa temizle.
    """
    try:
        prompt = (
            "You are an AI security analyst. Given the packet size in bytes, respond ONLY with:\n"
            "0 → Normal\n"
            "1 → Anomalous\n\n"
            f"Packet Size: {size}"
        )
        response = co.chat(
            message=prompt,
            model="command-light",
            temperature=0,
        )
        first_line = response.text.strip().splitlines()[0].strip()
        cleaned = ''.join(filter(str.isdigit, first_line))  # sadece rakamları al
        return cleaned if cleaned in ["0", "1"] else "Cohere-err:InvalidResponse"
    except Exception as e:
        return f"Cohere-err:{e}"



class NetSentinel:
    def __init__(self, t_threshold=5, p_threshold=10, log_file="traffic_log.csv"):
        self.t_thr = t_threshold
        self.p_thr = p_threshold
        self.log = log_file

        self.p_count = 0
        self.sizes = []
        self.ip_times = defaultdict(list)
        self.alerted = set()

        self.lower = None
        self.upper = None
        self.last_api_reset = time.time()
        self.api_call_count = 0

    def _sampler(self, pkt):
        if pkt.haslayer("IP") and pkt.haslayer("TCP"):
            self.sizes.append(len(pkt))

    def calc_stats(self):
        print("🟡 Collecting 50 packets for baseline…")
        sniff(filter="tcp", prn=self._sampler, store=0, count=50)
        mean, std = statistics.mean(self.sizes), statistics.stdev(self.sizes)
        self.lower, self.upper = mean - 1.5 * std, mean + 1.5 * std
        print(f"Mean {mean:.2f} | Std {std:.2f} → Normal {self.lower:.2f}–{self.upper:.2f}")

    def _local_label(self, size: int) -> str:
        return "Anomalous" if size < self.lower or size > self.upper else "Normal"

    def _handle(self, pkt):
        if not (pkt.haslayer("IP") and pkt.haslayer("TCP")):
            return
        self.p_count += 1

        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        src, dst = pkt["IP"].src, pkt["IP"].dst
        sp, dp = pkt["TCP"].sport, pkt["TCP"].dport
        size = len(pkt)
        local = self._local_label(size)

        now = time.time()
        self.ip_times[src].append(now)
        self.ip_times[src] = [t for t in self.ip_times[src] if now - t <= self.t_thr]
        if len(self.ip_times[src]) > self.p_thr and src not in self.alerted:
            print(f"⚠️  {src} exceeded {self.p_thr} pkts in {self.t_thr}s")
            self.alerted.add(src)

        # API rate limit kontrolü
        if self.api_call_count >= 10:
            since = time.time() - self.last_api_reset
            if since < 60:
                wait_time = 60 - since
                print(f"⏳ API limiti doldu, {wait_time:.1f} sn bekleniyor…")
                time.sleep(wait_time)
            self.last_api_reset = time.time()
            self.api_call_count = 0

        raw = cohere_assess_packet(size)
        self.api_call_count += 1
        ai = {"0": "Normal", "1": "Anomalous"}.get(raw, raw)

        print(f"{src}->{dst} | Size:{size:<4} | Local:{local:<9} | AI:{ai:<12} | Total:{self.p_count}")

        with open(self.log, "a", newline="") as f:
            csv.writer(f).writerow(
                [ts, src, dst, sp, dp, "TCP", size, local, ai]
            )

    def analyse(self):
        df = pd.read_csv(self.log)
        print("\n📄 First rows:\n", df.head())
        if df.empty:
            print("⚠️  No data.")
            return

        df["Packet Size"].plot.hist(bins=50, alpha=0.7)
        plt.title("Packet Size Distribution")
        plt.xlabel("Bytes")
        plt.ylabel("Freq")
        plt.grid()
        plt.show()

        print("\n📊 Stats:")
        print("Total:", len(df))
        print(df["Protocol"].value_counts(normalize=True).mul(100).round(2).astype(str) + "%")
        print(df.groupby("Protocol")["Packet Size"].agg(["mean", "min", "max"]).round(2))

    def run(self):
        with open(self.log, "w", newline="") as f:
            csv.writer(f).writerow(
                [
                    "Timestamp",
                    "IP Source",
                    "IP Destination",
                    "Source Port",
                    "Destination Port",
                    "Protocol",
                    "Packet Size",
                    "Local Label",
                    "AI Label",
                ]
            )

        self.calc_stats()
        print("🟢 Listening… Ctrl+C to stop.")
        try:
            sniff(filter="tcp", prn=self._handle, store=0)
        except KeyboardInterrupt:
            print("\n⛔ Stopped. Packets:", self.p_count)

        self.analyse()


if __name__ == "__main__":
    NetSentinel().run()
