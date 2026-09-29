#!/bin/bash
# =============================================================
#  RAQIB — CTF Mode
#  وضع المسابقات الأمنية (picoCTF / CTF competitions)
#  19 أداة موزعة على 5 تصنيفات:
#    Crypto | Stego | Forensics | Web | Binary
#  + Flag Hunter وضع البحث التلقائي عن الـ flags
# =============================================================

CTF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

menu_ctf_main() {
    while true; do
        show_banner
        echo -e "${BOLD}${CYAN}  ╔══════════════════════════════════════════╗${NC}"
        echo -e "${BOLD}${CYAN}  ║    🏴 RAQIB — CTF MODE  v2.2            ║${NC}"
        echo -e "${BOLD}${CYAN}  ╚══════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${CYAN}1)${NC} 🔐 Cryptography        — Base64/Hex/ROT/XOR/RSA/Vigenère"
        echo -e "  ${CYAN}2)${NC} 🖼️  Steganography        — LSB/Metadata/Magic Bytes/Audio"
        echo -e "  ${CYAN}3)${NC} 🔍 Forensics            — PCAP/File Carving/Timeline"
        echo -e "  ${CYAN}4)${NC} 🌐 Web Exploitation     — Headers/JWT/Cookies"
        echo -e "  ${CYAN}5)${NC} ⚙️  Binary / Reverse     — ELF/Packing/BOF Helper"
        echo -e "  ${YELLOW}6)${NC} 🏴 Flag Hunter          — ابحث عن flags في أي ملف/مجلد"
        echo -e "  ${GREEN}7)${NC} 📝 Writeup Logger       — سجّل خطوات الحل تلقائياً"
        echo -e "  ${RED}0)${NC} ↩  رجوع للقائمة الرئيسية"
        echo ""
        read -rp "  اختر: " choice
        case $choice in
            1) menu_ctf_crypto ;;
            2) menu_ctf_stego ;;
            3) menu_ctf_forensics ;;
            4) menu_ctf_web ;;
            5) menu_ctf_binary ;;
            6) run_tool "$CTF_DIR/flag_hunter.sh" ;;
            7) run_tool "$CTF_DIR/writeup_logger.sh" ;;
            0) return ;;
            *) echo -e "${RED}اختيار غير صحيح${NC}"; sleep 1 ;;
        esac
    done
}
export -f menu_ctf_main

menu_ctf_crypto() {
    while true; do
        show_banner
        echo -e "${BOLD}${CYAN}  🔐 Cryptography Tools${NC}"
        echo ""
        echo -e "  ${CYAN}1)${NC} Codec Swiss Army      — Base64/Hex/ROT13/ROT47/XOR/Caesar auto-detect"
        echo -e "  ${CYAN}2)${NC} Frequency Analysis    — تحليل تردد أحرف + خمّن الـ cipher"
        echo -e "  ${CYAN}3)${NC} RSA Helper            — Factoring / e=3 / Wiener attack"
        echo -e "  ${CYAN}4)${NC} Hash Identifier       — MD5/SHA1/SHA256/bcrypt/NTLM..."
        echo -e "  ${CYAN}5)${NC} Vigenère Cracker      — Kasiski + IC attack"
        echo -e "  ${RED}0)${NC} ↩  رجوع"
        echo ""
        read -rp "  اختر: " choice
        case $choice in
            1) run_tool "$CTF_DIR/crypto/01_codec_swiss_army.sh" ;;
            2) run_tool "$CTF_DIR/crypto/02_frequency_analysis.sh" ;;
            3) run_tool "$CTF_DIR/crypto/03_rsa_helper.sh" ;;
            4) run_tool "$CTF_DIR/crypto/04_hash_identifier.sh" ;;
            5) run_tool "$CTF_DIR/crypto/05_vigenere_cracker.sh" ;;
            0) return ;;
            *) echo -e "${RED}اختيار غير صحيح${NC}"; sleep 1 ;;
        esac
    done
}
export -f menu_ctf_crypto

menu_ctf_stego() {
    while true; do
        show_banner
        echo -e "${BOLD}${CYAN}  🖼️  Steganography Tools${NC}"
        echo ""
        echo -e "  ${CYAN}1)${NC} LSB Extractor         — استخراج LSB من PNG/BMP"
        echo -e "  ${CYAN}2)${NC} Metadata Reader       — EXIF + embedded strings"
        echo -e "  ${CYAN}3)${NC} Magic Bytes Check     — كشف polyglot + extension spoofing"
        echo -e "  ${CYAN}4)${NC} Audio Stego           — spectrogram hints + morse"
        echo -e "  ${RED}0)${NC} ↩  رجوع"
        echo ""
        read -rp "  اختر: " choice
        case $choice in
            1) run_tool "$CTF_DIR/stego/06_lsb_extractor.sh" ;;
            2) run_tool "$CTF_DIR/stego/07_metadata_reader.sh" ;;
            3) run_tool "$CTF_DIR/stego/08_magic_bytes_check.sh" ;;
            4) run_tool "$CTF_DIR/stego/09_audio_stego.sh" ;;
            0) return ;;
            *) echo -e "${RED}اختيار غير صحيح${NC}"; sleep 1 ;;
        esac
    done
}
export -f menu_ctf_stego

menu_ctf_forensics() {
    while true; do
        show_banner
        echo -e "${BOLD}${CYAN}  🔍 Forensics Tools${NC}"
        echo ""
        echo -e "  ${CYAN}1)${NC} PCAP Analyzer         — بدون Wireshark (tcpdump/strings)"
        echo -e "  ${CYAN}2)${NC} File Carver           — استخراج ملفات مخفية (binwalk-lite)"
        echo -e "  ${CYAN}3)${NC} Strings Hunter        — بحث ذكي عن flags + suspicious strings"
        echo -e "  ${CYAN}4)${NC} Timeline Builder      — بناء timeline من artifacts متعددة"
        echo -e "  ${RED}0)${NC} ↩  رجوع"
        echo ""
        read -rp "  اختر: " choice
        case $choice in
            1) run_tool "$CTF_DIR/forensics/10_pcap_analyzer.sh" ;;
            2) run_tool "$CTF_DIR/forensics/11_file_carver.sh" ;;
            3) run_tool "$CTF_DIR/forensics/12_strings_hunter.sh" ;;
            4) run_tool "$CTF_DIR/forensics/13_timeline_builder.sh" ;;
            0) return ;;
            *) echo -e "${RED}اختيار غير صحيح${NC}"; sleep 1 ;;
        esac
    done
}
export -f menu_ctf_forensics

menu_ctf_web() {
    while true; do
        show_banner
        echo -e "${BOLD}${CYAN}  🌐 Web Exploitation Tools${NC}"
        echo ""
        echo -e "  ${CYAN}1)${NC} Header Inspector      — HTTP headers + security misconfigs"
        echo -e "  ${CYAN}2)${NC} Cookie/JWT Decoder    — JWT + Flask session + cookie analysis"
        echo -e "  ${CYAN}3)${NC} Robots & Secrets      — robots.txt + hidden paths"
        echo -e "  ${RED}0)${NC} ↩  رجوع"
        echo ""
        read -rp "  اختر: " choice
        case $choice in
            1) run_tool "$CTF_DIR/web/14_header_inspector.sh" ;;
            2) run_tool "$CTF_DIR/web/15_cookie_decoder.sh" ;;
            3) run_tool "$CTF_DIR/web/16_robots_secrets.sh" ;;
            0) return ;;
            *) echo -e "${RED}اختيار غير صحيح${NC}"; sleep 1 ;;
        esac
    done
}
export -f menu_ctf_web

menu_ctf_binary() {
    while true; do
        show_banner
        echo -e "${BOLD}${CYAN}  ⚙️  Binary / Reverse Engineering Tools${NC}"
        echo ""
        echo -e "  ${CYAN}1)${NC} ELF Analyzer          — headers/sections/imports (بدون objdump إلزامي)"
        echo -e "  ${CYAN}2)${NC} Packing Detector      — UPX + common packer signatures"
        echo -e "  ${CYAN}3)${NC} BOF Helper            — buffer overflow offset + pattern gen"
        echo -e "  ${RED}0)${NC} ↩  رجوع"
        echo ""
        read -rp "  اختر: " choice
        case $choice in
            1) run_tool "$CTF_DIR/binary/17_elf_analyzer.sh" ;;
            2) run_tool "$CTF_DIR/binary/18_packing_detector.sh" ;;
            3) run_tool "$CTF_DIR/binary/19_bof_helper.sh" ;;
            0) return ;;
            *) echo -e "${RED}اختيار غير صحيح${NC}"; sleep 1 ;;
        esac
    done
}
export -f menu_ctf_binary
