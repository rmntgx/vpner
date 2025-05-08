#!/usr/bin/env bash
selected=$(vpner --list-rofi \
  | rofi -dmenu \
         -p "Select VPN Server" \
         -width 30 \
		 -format d \
		 -theme theme/style.rasi)

vpner "-$selected"