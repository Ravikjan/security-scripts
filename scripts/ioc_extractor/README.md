# Извлечение индикаторов компрометации

Находит в тексте IPv4/IPv6-адреса, домены, URL, хеши MD5/SHA1/SHA256 и
адреса почты. Умеет убирать приватные адреса, применять белый список и
готовить индикаторы к публикации.

```powershell
# Отчёт в консоль
python scripts/ioc_extractor/extract_iocs.py samples/threat_report.txt

# Безопасный для публикации вид
python scripts/ioc_extractor/extract_iocs.py report.txt --defang

# Только сетевые индикаторы, JSON, без приватных адресов
python scripts/ioc_extractor/extract_iocs.py report.txt --types ipv4,ipv6,domain \
    --exclude-private -o iocs.json
```

- `--refang-input` восстанавливает обезвреженные индикаторы (`1[.]2[.]3[.]4`).
- `--fail-on-ioc` даёт код 1, если что-то найдено — удобно для CI.
- Архивы, PDF и бинарные файлы не разбираются: подавайте текст.

Полное описание — в [docs/04-ИНДИКАТОРЫ.md](../../docs/04-ИНДИКАТОРЫ.md).
