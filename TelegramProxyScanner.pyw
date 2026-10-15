import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading, queue, urllib.request, urllib.parse, json, re, socket, time, os, sys, subprocess, shutil, traceback, platform, random, struct, hashlib, hmac, collections, ctypes, math, base64, html, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTOGRAPHY = True
except Exception:
    _HAS_CRYPTOGRAPHY = False

try:
    # Pillow рисует настоящие векторные значки на кнопках (вместо эмодзи) — если его
    # нет (например, Вариант Б из README без "pip install pillow"), программа тихо
    # возвращается к прежнему виду (эмодзи+подпись в тексте кнопки), без сбоя — см.
    # _make_icon ниже и его единственную точку вызова _set_btn_icon.
    from PIL import Image, ImageDraw, ImageTk
    _HAS_PIL = True
except Exception:
    _HAS_PIL = False

APP_TITLE = 'Telegram Proxy Scanner'
# Порог ширины окна (px), ниже которого интерфейс переключается в "узкий" режим:
# карточки параметров встают друг под друга, подписи кнопок сокращаются, а
# подзаголовок переносится по словам (см. _relayout).
RESPONSIVE_BREAKPOINT_WIDTH = 1280
# На вкладке "Настройка" карточки параметров при нехватке высоты окна НЕ раздувают
# окно сами и не обрезаются — вместо этого кладутся в прокручиваемую область и
# получают свой собственный скроллбар, уменьшаясь до SETTINGS_CANVAS_MIN_HEIGHT
# (см. _relayout). Вкладка "Сканирование" в этой прокрутке не нуждается — там
# результаты сами занимают всё свободное место, а таблица умеет прокручиваться сама.
SETTINGS_CANVAS_MIN_HEIGHT = 120
SETTINGS_VERTICAL_CHROME = 70  # отступы root + зазоры между блоками по вертикали (см. padding в _build_ui)
MIN_WINDOW_WIDTH = 700
MIN_WINDOW_HEIGHT = 480
UA = 'TelegramProxyScanner/6.0'
IPINFO = 'http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as,query'
TG_RE = re.compile(r'(?:tg://proxy|https?://t\.me/proxy)\?[^\s"\']+', re.I)
# "Другие виды прокси" публикуются не только как socks5://host:port / http://host:port
# (см. _TYPED_LINK_RE_TMPL), но и как готовые tg://-ссылки — ровно так же, как MTProto
# (tg://proxy?...). Подтверждено реальными источниками: kort0881/telegram-proxy-collector
# публикует SOCKS5 как "tg://socks?server=...&port=...", а WEB-прокси в самом Telegram
# Desktop делится ссылкой "tg://webproxy?server=...&secret=..." (это нашёл сам
# пользователь и подтвердилось при исследовании - см. комментарий у _check_web_proxy).
TG_SOCKS_RE = re.compile(r'(?:tg://socks|https?://t\.me/socks)\?[^\s"\']+', re.I)
TG_WEBPROXY_RE = re.compile(r'(?:tg://webproxy|https?://t\.me/webproxy)\?[^\s"\']+', re.I)
SOURCE_RE = re.compile(r'(?:proxy|mtproto|telegram).{0,80}(?:\.txt|\.json)', re.I)

COUNTRY_NAMES = {
    'AF':'Афганистан','AL':'Албания','DZ':'Алжир','AD':'Андорра','AO':'Ангола','AR':'Аргентина','AM':'Армения','AU':'Австралия','AT':'Австрия','AZ':'Азербайджан',
    'BH':'Бахрейн','BD':'Бангладеш','BY':'Беларусь','BE':'Бельгия','BZ':'Белиз','BJ':'Бенин','BT':'Бутан','BO':'Боливия','BA':'Босния и Герцеговина','BW':'Ботсвана','BR':'Бразилия','BN':'Бруней','BG':'Болгария','BF':'Буркина-Фасо','BI':'Бурунди',
    'KH':'Камбоджа','CM':'Камерун','CA':'Канада','CV':'Кабо-Верде','CF':'Центральноафриканская Республика','TD':'Чад','CL':'Чили','CN':'Китай','CO':'Колумбия','KM':'Коморы','CG':'Республика Конго','CD':'Демократическая Республика Конго','CR':'Коста-Рика','CI':'Кот-д’Ивуар','HR':'Хорватия','CU':'Куба','CY':'Кипр','CZ':'Чехия',
    'DK':'Дания','DJ':'Джибути','DO':'Доминиканская Республика','EC':'Эквадор','EG':'Египет','SV':'Сальвадор','EE':'Эстония','ET':'Эфиопия','FI':'Финляндия','FR':'Франция','GE':'Грузия','DE':'Германия','GH':'Гана','GR':'Греция','GT':'Гватемала','HN':'Гондурас','HK':'Гонконг','HU':'Венгрия','IS':'Исландия','IN':'Индия','ID':'Индонезия','IR':'Иран','IQ':'Ирак','IE':'Ирландия','IL':'Израиль','IT':'Италия','JP':'Япония','JO':'Иордания','KZ':'Казахстан','KE':'Кения','KR':'Южная Корея','KW':'Кувейт','KG':'Кыргызстан','LV':'Латвия','LB':'Ливан','LT':'Литва','LU':'Люксембург','MY':'Малайзия','MV':'Мальдивы','MT':'Мальта','MX':'Мексика','MD':'Молдова','MC':'Монако','MN':'Монголия','ME':'Черногория','MA':'Марокко','MZ':'Мозамбик','MM':'Мьянма','NA':'Намибия','NP':'Непал','NL':'Нидерланды','NZ':'Новая Зеландия','NI':'Никарагуа','NG':'Нигерия','MK':'Северная Македония','NO':'Норвегия','OM':'Оман','PK':'Пакистан','PA':'Панама','PY':'Парагвай','PE':'Перу','PH':'Филиппины','PL':'Польша','PT':'Португалия','QA':'Катар','RO':'Румыния','RU':'Россия','SA':'Саудовская Аравия','RS':'Сербия','SG':'Сингапур','SK':'Словакия','SI':'Словения','ZA':'Южно-Африканская Республика','ES':'Испания','LK':'Шри-Ланка','SE':'Швеция','CH':'Швейцария','TW':'Тайвань','TJ':'Таджикистан','TH':'Таиланд','TN':'Тунис','TR':'Турция','TM':'Туркменистан','UA':'Украина','AE':'ОАЭ','GB':'Великобритания','US':'США','UY':'Уругвай','UZ':'Узбекистан','VE':'Венесуэла','VN':'Вьетнам','YE':'Йемен','ZM':'Замбия','ZW':'Зимбабве'
}
COLORS={
    'bg':'#0a0e17','bg2':'#0d1220',
    'panel':'#121a2b','panel2':'#1a2439','panel3':'#0e1524',
    'input':'#0d1422','border':'#28334c','border_soft':'#1c2740',
    'text':'#f5f7fb','muted':'#8d9ab0','muted2':'#5c6886',
    'accent':'#6172ff','accent2':'#9a6bff','hover':'#7b89ff',
    'green':'#22c55e','green_bg':'#0f2a1f','green_text':'#86efac',
    'red':'#ef4444','red_bg':'#2a1318','red_text':'#ffb4bf',
    'yellow':'#f5a524','yellow_bg':'#2a2110','yellow_text':'#fcd34d',
    'blue':'#38bdf8','white':'#ffffff',
}

STATIC_SOURCES = [
    # Каждая запись — это (имя_для_отображения, raw-URL). Все адреса ниже проверены вручную
    # (содержимое реально содержит рабочие ссылки tg://proxy?server=...&secret=...).
    # Основной проект и его многочисленные независимые форки/зеркала (полезны как
    # запасные копии друг друга — если один форк не обновляется или недоступен, почти
    # наверняка сработает другой):
    ('SoliSpirit', 'https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt'),
    ('ALIILAPRO', 'https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt'),
    ('Grim1313', 'https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/master/all_proxies.txt'),
    ('neobxod', 'https://raw.githubusercontent.com/neobxod/mtproto-for-telegram/master/all_proxies.txt'),
    ('mcny2809', 'https://raw.githubusercontent.com/mcny2809/mtproto-for-telegram/master/all_proxies.txt'),
    ('userg0d', 'https://raw.githubusercontent.com/userg0d/mtproto/master/all_proxies.txt'),
    ('dongbo1981416', 'https://raw.githubusercontent.com/dongbo1981416/mtproto/master/all_proxies.txt'),
    ('KamishiroIyamoto', 'https://raw.githubusercontent.com/KamishiroIyamoto/mtproto-proxies-list/master/all_proxies.txt'),
    ('Forca423', 'https://raw.githubusercontent.com/Forca423/mtproto-for-telegram/master/all_proxies.txt'),
    ('Aniskhoso', 'https://raw.githubusercontent.com/Aniskhoso/mtproto/master/all_proxies.txt'),
    ('pardisan055-lab', 'https://raw.githubusercontent.com/pardisan055-lab/mtproto/master/all_proxies.txt'),
    ('tgproxy-pages', 'https://tgproxy.l1979.ru/proxies.txt'),
    ('tgmtproxy-pages', 'https://tgmtproxy.github.io/mtproxy/proxies.txt'),
    ('zakky8-pages', 'https://zakky8.github.io/mtproto-proxy-pro/all_proxies.txt'),
    ('zakky8', 'https://raw.githubusercontent.com/zakky8/mtproto-proxy-pro/main/README.md'),
    # Независимые проекты со своими собственными списками:
    ('tgmtproxy', 'https://raw.githubusercontent.com/tgmtproxy/telegram-mtproto-proxy-list/main/proxies.txt'),
    ('tgmtproxy2', 'https://raw.githubusercontent.com/tgmtproxy/mtproxy/main/proxies.txt'),
    ('ferhatacer90', 'https://raw.githubusercontent.com/ferhatacer90/mtproxy-list/main/proxies.txt'),
    ('anonymouskeys', 'https://raw.githubusercontent.com/anonymouskeys/mtproto/main/proxies.txt'),
    ('Iliya3ProX', 'https://raw.githubusercontent.com/Iliya3ProX/good_proxies/main/proxies.txt'),
    ('Chumbayoumba', 'https://raw.githubusercontent.com/Chumbayoumba/free-telegram-proxy-russia-2026/main/README.md'),
    ('oznurakaro04', 'https://raw.githubusercontent.com/oznurakaro04/telegram-proxy-live/main/proxies.txt'),
    ('Argh94-scraper', 'https://raw.githubusercontent.com/Argh94/telegram-proxy-scraper/main/proxy.txt'),
    ('Argh94-list', 'https://raw.githubusercontent.com/Argh94/Proxy-List/main/MTProto.txt'),
    ('iwh3n', 'https://raw.githubusercontent.com/iwh3n/tg-proxy/main/proxys/All_Proxys.txt'),
    ('Telegram-FZ-LLC', 'https://raw.githubusercontent.com/Telegram-FZ-LLC/Telegram-Proxy/main/proxies.txt'),
    ('aviamastersgh', 'https://raw.githubusercontent.com/aviamastersgh/mtproto-free-russia/main/all_proxies.txt'),
    ('TETRIX8', 'https://raw.githubusercontent.com/TETRIX8/mtproxy-list-updater/main/proxies.json'),
    ('chelaxian', 'https://raw.githubusercontent.com/chelaxian/freetelemt/main/proxies.txt'),
    ('mmbateni', 'https://raw.githubusercontent.com/mmbateni/iran-telegram-proxies/main/output/proxies.txt'),
    ('dubblebyte', 'https://raw.githubusercontent.com/dubblebyte/free-mtproto-proxies/main/all_proxies.txt'),
    ('leshchenko1979', 'https://raw.githubusercontent.com/leshchenko1979/tgproxy/main/docs/proxies.txt'),
    ('Kira00011', 'https://raw.githubusercontent.com/Kira00011/MTProto/main/all_proxies.txt'),
    ('helptmoop-1', 'https://raw.githubusercontent.com/helptmoop/Free-Telegram-Proxies/main/global-iran-russia-proxies.txt'),
    ('helptmoop-2', 'https://raw.githubusercontent.com/helptmoop/Free-Telegram-Proxies/main/turkmenistan-global-iran-russia.txt'),
    ('kort0881-ru', 'https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_ru.txt'),
    ('kort0881-eu', 'https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_eu.txt'),
    ('kort0881-all', 'https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_all.txt'),
    ('shablin', 'https://raw.githubusercontent.com/shablin/mtproto-proxy/main/README.md'),
    # Открытые тг-каналы, добавленные в статичные источники по просьбе пользователя
    # (пункт №3 обращения) — URL вида tgchannel://<имя> это не настоящий URL, а
    # признак для load_sources()/_load_channel_source(): вместо обычного http_get
    # скачиваются последние TELEGRAM_CHANNEL_MESSAGE_LIMIT сообщений канала через
    # его открытую веб-версию (см. fetch_telegram_channel_text) и из текста сообщений
    # достаются прокси-ссылки — точно так же, как сейчас работает "Улучшенный поиск"
    # для похожих каналов (см. ENHANCED_SEED_CHANNELS ниже).
    ('tg:urlsources', 'tgchannel://urlsources'),
    ('tg:gidroski', 'tgchannel://gidroski'),
]

# v30 (пункт №1 обращения): вместо одной галочки «Включить другие виды прокси» —
# отдельный выбор по видам: MTProto, SOCKS5, HTTP, WEB (см. PROXY_TYPES и четыре
# галочки ptype_* в настройках). Каждый выбранный вид получает СВОЙ поиск: свои готовые
# списки (TYPED_STATIC_SOURCES), свои запросы к GitHub (DISCOVERY_QUERIES_BY_TYPE), свои
# имена файлов (COMMON_FILENAMES_BY_TYPE), свою проверку содержимого найденного источника
# (sample_matches_type) и свой разбор (parse_proxies(types=...)/parse_typed_links).
# Невыбранные виды не ищутся, не разбираются и не проверяются вообще.
# Для каждого типа действительно нужна своя проверка (как и предупреждал пользователь):
# SOCKS5/HTTP — полное рукопожатие + CONNECT до core.telegram.org, WEB — настоящее TLS+
# HTTPS (см. _check_web_proxy; сам «мост» WEB Telegram публично не документирует, поэтому
# глубже честно не проверяется).
PROXY_TYPES = ('mtproto', 'socks5', 'http', 'web')

# Готовые списки по типам. Все адреса проверены вручную (v30): отдают живые списки.
# kort0881-SOCKS5 публикует SOCKS5 как готовые "tg://socks?server=...&port=..." ссылки,
# поэтому НЕ в OTHER_SOURCE_TYPES ниже: разбирается обычным parse_proxies(types=...),
# который понимает оба формата (см. TG_SOCKS_RE). Готового публичного списка именно
# WEB-ссылок пока нет (формат новый) — они ищутся в тексте тг-каналов и найденных
# источников (parse_webproxy_link), см. DISCOVERY_QUERIES_BY_TYPE['web'].
TYPED_STATIC_SOURCES = {
    'socks5': [
        ('Argh94-SOCKS5', 'https://raw.githubusercontent.com/Argh94/Proxy-List/main/SOCKS5.txt'),
        ('kort0881-SOCKS5', 'https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/socks5.txt'),
        ('TheSpeedX-SOCKS5', 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt'),
        ('monosans-SOCKS5', 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt'),
        ('jetkai-SOCKS5', 'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt'),
    ],
    'http': [
        ('Argh94-HTTP', 'https://raw.githubusercontent.com/Argh94/Proxy-List/main/HTTP.txt'),
        ('TheSpeedX-HTTP', 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt'),
        ('monosans-HTTP', 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt'),
        ('jetkai-HTTP', 'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt'),
    ],
    'web': [],
}
# Совместимость со старым именем (плоский список всех «не-MTProto» готовых источников).
OTHER_PROXY_SOURCES = [s for t in ('socks5', 'http', 'web') for s in TYPED_STATIC_SOURCES[t]]
# url -> тип прокси в этом источнике (load_sources() разбирает такой файл через
# parse_typed_links вместо parse_proxies — файл целиком одного типа в формате
# host:port / scheme://host:port, тип по строкам угадывать не нужно). Источники с
# готовыми tg://-ссылками сюда НЕ добавляются — см. выше.
OTHER_SOURCE_TYPES = {
    'https://raw.githubusercontent.com/Argh94/Proxy-List/main/SOCKS5.txt': 'socks5',
    'https://raw.githubusercontent.com/Argh94/Proxy-List/main/HTTP.txt': 'http',
    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt': 'socks5',
    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt': 'http',
    'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt': 'socks5',
    'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt': 'http',
    'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt': 'socks5',
    'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt': 'http',
}
# Типы источников, найденных ДИНАМИЧЕСКИ (discover_sources): url -> 'socks5'/'http' для
# «голых» списков host:port (как OTHER_SOURCE_TYPES, но заполняется на лету).
_SOURCE_TYPE_HINTS = {}

def normalize_types(types):
    """Приводит набор видов прокси к каноническому кортежу в порядке PROXY_TYPES; None —
    «как раньше», только MTProto. Неизвестные значения отбрасываются."""
    if types is None: return ('mtproto',)
    s = {t for t in types if t in PROXY_TYPES}
    return tuple(t for t in PROXY_TYPES if t in s)

def enabled_types_from_settings(d):
    """Какие виды прокси включены в словаре настроек. Новые ключи ptype_<вид>; если их
    нет вовсе (файл настроек от версии ≤v29) — старая галочка other_proxy_types: True
    включала SOCKS5+HTTP+WEB дополнительно к MTProto. Может вернуть пустой кортеж
    (пользователь снял все галочки) — вызывающий код обязан это обработать."""
    if any(('ptype_'+t) in d for t in PROXY_TYPES):
        return tuple(t for t in PROXY_TYPES if d.get('ptype_'+t, t == 'mtproto'))
    if d.get('other_proxy_types'): return PROXY_TYPES
    return ('mtproto',)

def typed_sources_for(types):
    """Готовые списки (name,url) для выбранных видов, в порядке PROXY_TYPES."""
    out = []
    for t in normalize_types(types):
        out.extend(TYPED_STATIC_SOURCES.get(t, []))
    return out

# Подписи типа прокси для колонки "Тип" в таблице результатов (пункт №1 обращения).
PTYPE_LABELS = {'mtproto':'MTProto','socks5':'SOCKS5','http':'HTTP','web':'WEB'}

# Сколько последних сообщений канала просматривать (пункты №2 и №3 обращения: "смотреть
# будем последние 50 сообщений"), и защитный предел на число подряд идущих запросов
# страницы (~20-25 сообщений за один запрос — см. fetch_telegram_channel_text), чтобы
# даже при аномалии (например, сервер всегда отдаёт одни и те же id) не уйти в цикл.
TELEGRAM_CHANNEL_MESSAGE_LIMIT = 50
TELEGRAM_CHANNEL_MAX_PAGES = 6

# Filenames real MTProto-list repositories commonly use for their published list.
# Tried directly against raw.githubusercontent.com first during dynamic discovery,
# since that costs no GitHub API quota (unlike listing a repo's file tree).
COMMON_PROXY_FILENAMES = [
    'all_proxies.txt','proxies.txt','proxy.txt','mtproto.txt','MTProto.txt','list.txt',
    'proxies.json','proxys/All_Proxys.txt','output/proxies.txt','docs/proxies.txt',
    'data/proxies.txt','proxy_all.txt','all_proxies.md',
    # Доп. варианты имён/путей: реальный разброс у публичных репозиториев с прокси-листами
    # гораздо шире этого исходного списка — большинство попыток по именам 404-тся впустую
    # (замерено логом: лишь ~2% угаданных путей реально существуют), поэтому расширение
    # списка напрямую увеличивает долю находок без единого лишнего обращения к GitHub API.
    'README.md','readme.md','Readme.md','config.txt','sub.txt','subscribe.txt',
    'mtproto_proxies.txt','mtproto-proxies.txt','telegram_proxies.txt','telegram-proxies.txt',
    'proxy_list.txt','proxylist.txt','ProxyList.txt','proxies/all.txt','proxies/proxies.txt',
    'list/proxies.txt','result.txt','results.txt','best.txt','working.txt','active.txt',
    'proxies/mtproto.txt','assets/proxies.txt','src/proxies.txt','export/proxies.txt',
]

# Search queries used for dynamic discovery. "topic:" queries match GitHub's own repo
# topic tags (e.g. repos explicitly tagged "mtproto-proxy"), which is far more precise
# than free-text search; the free-text and non-English queries widen the net to repos
# that publish lists without using those exact topic tags.
DISCOVERY_QUERIES = [
    'topic:mtproto-proxy','topic:telegram-proxy-list','topic:mtproxy','topic:free-proxy-list',
    'telegram mtproto proxy list','mtproto proxies telegram','telegram proxy list txt',
    'прокси telegram mtproto','mtproto прокси телеграм','free mtproto proxy github',
    'لیست پروکسی تلگرام mtproto','telegram proxy iran mtproto',
]

# v30: запросы и имена файлов ПО ВИДАМ прокси (discover_sources выполняет только те, что
# относятся к выбранным видам). У каждого вида своя экосистема репозиториев: у SOCKS5/HTTP —
# огромные универсальные списки (topic:socks5-proxy, proxy-list…), у WEB — совсем новый
# формат tg://webproxy (репозиториев почти нет, поэтому WEB в основном ищется в тексте
# тг-каналов и страницах улучшенного поиска). Запросов у не-MTProto видов намного меньше —
# лимит GitHub Search API общий (~10/мин без токена), см. discover_sources.
DISCOVERY_QUERIES_BY_TYPE = {
    'mtproto': DISCOVERY_QUERIES,
    'socks5': ['topic:socks5-proxy', 'topic:socks5', 'socks5 proxy list', 'free socks5 proxy list telegram'],
    'http': ['topic:http-proxy', 'topic:proxy-list', 'http proxy list', 'free http proxy list'],
    'web': ['telegram webproxy', 'tg://webproxy list'],
}
COMMON_FILENAMES_BY_TYPE = {
    'mtproto': COMMON_PROXY_FILENAMES,
    'socks5': ['socks5.txt','SOCKS5.txt','socks5_proxies.txt','socks5-proxies.txt','proxies/socks5.txt',
               'proxies-socks5.txt','socks5/data.txt','proxies/protocols/socks5/data.txt','socks.txt',
               'proxy.txt','proxies.txt','all.txt','list.txt','README.md'],
    'http': ['http.txt','HTTP.txt','https.txt','http_proxies.txt','http-proxies.txt','proxies/http.txt',
             'proxies-http.txt','http/data.txt','proxies/protocols/http/data.txt','proxy.txt','proxies.txt',
             'all.txt','list.txt','README.md'],
    'web': ['webproxy.txt','web.txt','web_proxies.txt','proxies.txt','proxy.txt','all_proxies.txt','README.md'],
}

# Содержимое найденного кандидата проверяется ПО ВИДУ (никогда по одному имени файла):
# MTProto — ссылки с secret=/t.me/proxy; SOCKS5/HTTP — много строк host:port (с/без схемы)
# либо tg://socks; WEB — хотя бы одна ссылка tg://webproxy.
_IPPORT_LINE_RE = re.compile(r'^\s*(?:(?:socks5|http|https)://)?(?:[^:@/\s]{1,64}:[^@/\s]{0,64}@)?\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\s*$', re.M)

def sample_matches_type(sample, ptype):
    if not sample: return False
    if ptype == 'mtproto':
        return sample.count('secret=') >= 2 or len(re.findall(r't\.me/proxy', sample)) >= 2
    if ptype in ('socks5', 'http'):
        if ptype == 'socks5' and len(TG_SOCKS_RE.findall(sample)) >= 2: return True
        return len(_IPPORT_LINE_RE.findall(sample)) >= 10
    if ptype == 'web':
        return len(TG_WEBPROXY_RE.findall(sample)) >= 1
    return False

def _guess_list_type(url):
    """Тип «голого» списка host:port по пути файла: 'socks5' / 'http' / 'socks4' (такие
    списки не поддерживаются — отбрасываются) / None, если по имени не понять."""
    try: path = urllib.parse.urlparse(url).path.lower()
    except Exception: return None
    if 'socks4' in path: return 'socks4'
    if 'socks' in path: return 'socks5'
    if 'http' in path: return 'http'
    return None

# "Улучшенный поиск" (enhanced=True): помимо GitHub, источниками также считаются
# открытые тг-каналы и сайты, которые публикуют прокси-ссылки напрямую на своих
# страницах. Список ниже — проверенные вручную отправные точки (seed-список); сверх
# него enhanced-режим запускает ещё и текстовый веб-поиск (см. ENHANCED_SEARCH_QUERIES),
# чтобы находить и другие подобные каналы/сайты/форумы, а не только эти константы.
ENHANCED_SEED_CHANNELS = [
    'MTProxy4free', 'mtprx', 'MTProxyLists', 'MTProtoProxies', 'proxy_mtproto', 'mtprotoproxy_fast',
    'urlsources',  # добавлен по просьбе пользователя (пример: t.me/urlsources/43266)
    'gidroski',    # добавлен по просьбе пользователя — активно публикует рабочие mtproto-прокси
]
ENHANCED_SEED_WEBSITES = [
    'https://mtproxy.fyi/', 'https://mtprotolist.bond/', 'https://toproxylab.com/', 'https://mtpro.xyz/',
]
# Расширен охват "Улучшенного поиска": больше формулировок (RU/EN) и под-тематик (каналы со
# СПИСКАМИ каналов-источников — как urlsources выше, — не только сами прокси-листы), чтобы
# живой веб-поиск находил более широкий круг каналов/сайтов, а не только 4 узкие фразы.
ENHANCED_SEARCH_QUERIES = [
    'telegram mtproto proxy list site:t.me',
    'mtproto proxy канал телеграм список',
    'free mtproto proxy website list',
    'telegram proxy forum mtproto secret',
    'telegram канал прокси подборка ссылок t.me',
    'best telegram mtproto proxies 2026 channel',
    'рабочие прокси телеграм канал подключиться',
    'telegram proxy list updated daily channel',
]

# Скорость динамического поиска: раньше поиск шёл практически последовательно
# (запрос за запросом, репозиторий за репозиторием) и мог занимать минуты. Теперь все
# кандидаты (репозитории x имена файлов, плюс seed-каналы/сайты и результаты веб-поиска
# в enhanced-режиме) собираются в один список и проверяются ОДНИМ общим пулом потоков,
# а вся функция ограничена жёстким дедлайном по времени — поэтому пользователь ждёт
# секунды, а не часы, даже если часть кандидатов недоступна или отвечает медленно.
DISCOVERY_PROBE_WORKERS = 64
DISCOVERY_TIME_BUDGET = 18.0            # сек. — обычный динамический поиск (только GitHub)
DISCOVERY_TIME_BUDGET_ENHANCED = 30.0   # сек. — улучшенный поиск (GitHub + каналы/сайты + веб-поиск)
# Раньше было 900 — при per_page=25 и ~13 именах файлов этого хватало впритык, а с ростом
# per_page до 100 и расширенным списком имён файлов кандидатов стало в разы больше; предел
# поднят, чтобы реальным ограничителем снова был дедлайн по времени, а не искусственный
# обрыв списка кандидатов до того, как пул потоков успел их все перебрать (ровно это и было
# причиной недобора "40 запросили — 15-20 нашли": пул упирался в пустой список кандидатов
# за секунды до дедлайна, а не в сам дедлайн).
MAX_DISCOVERY_CANDIDATES = 4000

# Внутренние повторные попытки ВНУТРИ одного discover_sources(): GitHub Search API без
# авторизации ограничен ~10 запросами/минуту суммарно на все 11 запросов сразу — если этот
# лимит исчерпан (например, пользователь только что запускал поиск), GitHub отвечает
# 403/429 и discover_sources раньше просто завершался почти мгновенно с found=0..1, даже
# если пользователь выделил на поиск 60 секунд (отсюда и жалобы "всегда завершается раньше
# времени" и "результат рандомный"). Теперь при нехватке кандидатов/лимита, если время
# позволяет, функция делает паузу (больше — если это был именно rate-limit) и повторяет
# попытку — так используется всё отведённое пользователем время, а не только первые доли
# секунды. Это НЕ то же самое, что пользовательский параметр "Попыток дозапроса" ниже: это
# лишь безопасный предел на число таких внутренних повторов внутри одного вызова.
MAX_DISCOVERY_INTERNAL_RETRIES = 8

# "Дозапрос" источников, когда рабочих прокси набралось меньше, чем запросил пользователь
# (пункт №2 из обращения: "при нехватке прокси программа ищет ещё источники и продолжает
# поиск"). Число раундов настраивается пользователем (см. "Попыток дозапроса" в UI,
# settings['topup_rounds']) — значение ниже используется только как значение по умолчанию.
# Суммарный потолок времени на все раунды считается в scan() от самих настроек пользователя
# (раунды × «Время поиска») — раньше он был отдельной жёстко зашитой константой, из-за чего
# при увеличении «Попыток дозапроса» часть раундов молча не успевала выполниться (баг из
# обращения: "поставил 5, выполнилось только 2").
MAX_TOPUP_ROUNDS = 2
TOPUP_DISCOVERY_TIME_BUDGET = 15.0   # сек. — минимальный бюджет на поиск источников в одном раунде дозапроса



LOG_LOCK = threading.Lock()

def _log_path():
    base = os.path.dirname(os.path.abspath(sys.argv[0]))
    path = os.path.join(base, 'TelegramProxyScanner_debug.log')
    try:
        with open(path, 'a', encoding='utf-8'):
            pass
        return path
    except Exception:
        return os.path.join(os.path.expanduser('~'), 'TelegramProxyScanner_debug.log')

LOG_FILE = _log_path()
SETTINGS_FILE = os.path.join(os.path.dirname(LOG_FILE), 'TelegramProxyScanner_settings.json')

FONT_REGULAR_FILE = 'InterUI-Regular.ttf'
FONT_SEMIBOLD_FILE = 'InterUI-SemiBold.ttf'

def _load_bundled_fonts():
    """Пытается подключить более современный шрифт Inter — он лежит рядом с
    программой двумя файлами (обычное и полужирное начертание) — как приватный
    шрифт ТЕКУЩЕГО ПРОЦЕССА через WinAPI AddFontResourceExW: это не требует прав
    администратора, не устанавливает шрифт в систему и не трогает другие
    программы, а сам шрифт автоматически "забывается" при закрытии окна.
    Если файлов нет рядом (например, их забыли скопировать вместе со
    скриптом/.exe), система не на Windows, либо подключить не удалось по любой
    другой причине — тихо возвращает False, и программа использует Segoe UI,
    как и раньше (см. _build_styles) — сбоя при этом не происходит."""
    if os.name != 'nt':
        return False
    base = os.path.dirname(LOG_FILE)
    ok = False
    try:
        FR_PRIVATE = 0x10
        gdi32 = ctypes.WinDLL('gdi32')
        for fname in (FONT_REGULAR_FILE, FONT_SEMIBOLD_FILE):
            path = os.path.join(base, fname)
            if os.path.isfile(path) and gdi32.AddFontResourceExW(path, FR_PRIVATE, 0) > 0:
                ok = True
    except Exception:
        pass
    return ok

_INTER_AVAILABLE = _load_bundled_fonts()

# ---------------------------------------------------------------------------
# Значки на кнопках: настоящие векторные иконки вместо эмодзи (нарисованы
# кодом через Pillow, а не загружены откуда-то файлами — значит, не нужно
# тащить с программой ещё и папку картинок). Каждая функция рисует один
# значок в квадрате m×m пикселей одним цветом (цвет зависит от того, на какой
# кнопке значок стоит — см. _ICON_COLOR_BY_KIND в App._set_btn_icon). Рисуется
# значок в 4-кратном размере и затем уменьшается с сглаживанием (LANCZOS) —
# это даёт чёткие ровные линии на любом масштабе экрана. Если Pillow не
# установлен (_HAS_PIL=False) — ни одна из этих функций не вызывается, и
# кнопки просто остаются с текстом, как раньше.
ICON_SUPERSAMPLE = 4

def _ic_search(d, m, c):
    """Лупа — значок вкладки "Сканирование" (переход на вкладку)."""
    w = max(2, round(m * 0.085))
    cx, cy, r = m * 0.42, m * 0.42, m * 0.24
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=c, width=w)
    ang = math.radians(45)
    x0, y0 = cx + math.cos(ang) * r, cy + math.sin(ang) * r
    d.line([x0, y0, m * 0.82, m * 0.82], fill=c, width=w + 1)

def _ic_play(d, m, c):
    """Треугольник "play" — кнопка запуска сканирования."""
    pad = m * 0.22
    d.polygon([(pad, m * 0.15), (pad, m * 0.85), (m - pad * 0.75, m * 0.5)], fill=c)

def _ic_stop(d, m, c):
    """Квадрат — кнопка остановки сканирования."""
    pad = m * 0.24
    d.rounded_rectangle([pad, pad, m - pad, m - pad], radius=m * 0.08, fill=c)

def _ic_gear(d, m, c):
    """Шестерёнка — значок вкладки "Настройка"."""
    cx = cy = m * 0.5
    r_outer, r_inner, w = m * 0.30, m * 0.13, max(2, round(m * 0.065))
    d.ellipse([cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer], outline=c, width=w)
    d.ellipse([cx - r_inner, cy - r_inner, cx + r_inner, cy + r_inner], outline=c, width=w)
    teeth, tw, tl = 8, m * 0.11, m * 0.12
    for i in range(teeth):
        ang = 2 * math.pi * i / teeth
        bx, by = cx + math.cos(ang) * r_outer, cy + math.sin(ang) * r_outer
        ex, ey = cx + math.cos(ang) * (r_outer + tl), cy + math.sin(ang) * (r_outer + tl)
        px, py = -math.sin(ang) * tw / 2, math.cos(ang) * tw / 2
        d.polygon([(bx + px, by + py), (bx - px, by - py), (ex - px, ey - py), (ex + px, ey + py)], fill=c)

def _ic_save(d, m, c):
    """Дискета (упрощённая, плоская) — кнопка "Сохранить настройки"."""
    w = max(2, round(m * 0.06))
    pad = m * 0.15
    d.rounded_rectangle([pad, pad, m - pad, m - pad], radius=m * 0.10, outline=c, width=w)
    d.line([pad + m * 0.10, pad + m * 0.28, m - pad - m * 0.10, pad + m * 0.28], fill=c, width=w)
    d.rounded_rectangle([pad + m * 0.18, m - pad - m * 0.32, m - pad - m * 0.18, m - pad - m * 0.08], radius=m * 0.03, outline=c, width=w)

def _ic_folder(d, m, c):
    """Папка — кнопка "Загрузить настройки"."""
    w = max(2, round(m * 0.06))
    d.rounded_rectangle([m * 0.14, m * 0.22, m * 0.48, m * 0.34], radius=m * 0.035, outline=c, width=w)
    d.rounded_rectangle([m * 0.14, m * 0.32, m * 0.86, m * 0.80], radius=m * 0.06, outline=c, width=w)

def _ic_document(d, m, c):
    """Лист с загнутым уголком и строчками текста — кнопка "Лог"."""
    w = max(2, round(m * 0.055))
    pad, fold = m * 0.20, m * 0.18
    d.polygon([(pad, pad), (m - pad - fold, pad), (m - pad, pad + fold), (m - pad, m - pad), (pad, m - pad)], outline=c, width=w)
    d.line([m - pad - fold, pad, m - pad - fold, pad + fold, m - pad, pad + fold], fill=c, width=w)
    for frac in (0.48, 0.63, 0.78):
        d.line([pad + m * 0.11, m * frac, m - pad - m * 0.11, m * frac], fill=c, width=max(2, round(m * 0.035)))

def _ic_download(d, m, c):
    """Стрелка вниз в лоток — кнопка "Экспорт"."""
    w = max(2, round(m * 0.075))
    cx = m * 0.5
    d.line([cx, m * 0.13, cx, m * 0.56], fill=c, width=w)
    ah = m * 0.17
    d.polygon([(cx - ah, m * 0.52), (cx + ah, m * 0.52), (cx, m * 0.52 + ah * 1.1)], fill=c)
    d.line([m * 0.16, m * 0.82, m * 0.84, m * 0.82], fill=c, width=w)
    d.line([m * 0.16, m * 0.82, m * 0.16, m * 0.68], fill=c, width=w)
    d.line([m * 0.84, m * 0.82, m * 0.84, m * 0.68], fill=c, width=w)

_ICON_DRAW = {
    'search': _ic_search, 'play': _ic_play, 'stop': _ic_stop, 'gear': _ic_gear,
    'save': _ic_save, 'folder': _ic_folder, 'document': _ic_document, 'download': _ic_download,
}
_ICON_CACHE = {}

def _make_icon(name, color_hex, size=20):
    """Рисует (или берёт из кэша) значок `name` цветом `color_hex` в виде
    tkinter.PhotoImage. Возвращает None, если Pillow недоступен или имя
    значка не из списка выше — вызывающий код в этом случае просто не
    выставляет кнопке картинку, и она остаётся как была (текст с эмодзи)."""
    if not _HAS_PIL:
        return None
    fn = _ICON_DRAW.get(name)
    if fn is None:
        return None
    key = (name, color_hex, size)
    cached = _ICON_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        # Реальный баг, пойманный по логу пользователя: COLORS['white'] одно время был
        # задан как короткая форма '#fff' вместо '#ffffff' - эта функция ожидает только
        # полную 6-значную форму, а на коротком '#fff' ломалась (color_hex[5:7] давал
        # '', int('',16) падал) каждый раз, когда рисовалась белая иконка (кнопка
        # "Сканировать" и активная вкладка) - значки молча откатывались на эмодзи.
        # Теперь поддерживаются обе формы, чтобы такой же баг не мог повториться тихо.
        ch = color_hex.lstrip('#')
        if len(ch) == 3: ch = ''.join(c*2 for c in ch)
        rgb = tuple(int(ch[i:i+2], 16) for i in (0, 2, 4))
        big = size * ICON_SUPERSAMPLE
        img = Image.new('RGBA', (big, big), (0, 0, 0, 0))
        fn(ImageDraw.Draw(img), big, rgb + (255,))
        img = img.resize((size, size), Image.LANCZOS)
        photo = ImageTk.PhotoImage(img)
        _ICON_CACHE[key] = photo
        return photo
    except Exception:
        log('icon render failed: ' + name, exc=True)
        return None

def log(msg, exc=False):
    stamp = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f'[{stamp}] {msg}'
    if exc:
        line += '\n' + traceback.format_exc()
    try:
        with LOG_LOCK:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
    except Exception:
        pass

def _decode_console_bytes(b):
    """Windows console tools (powershell.exe, curl.exe) usually write diagnostic text in
    the OEM/ANSI console codepage, not UTF-8, which is why error messages in the debug
    log could show up as mojibake. Try the common Windows codepages before giving up."""
    for enc in ('utf-8','cp866','cp1251','mbcs'):
        try: return b.decode(enc)
        except Exception: continue
    return b.decode('utf-8','replace')

def http_get(url, timeout=12, extra_headers=None):
    errors=[]
    headers={
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36',
        'Accept':'text/plain,application/json,text/csv,*/*',
        'Accept-Language':'en-US,en;q=0.9',
        'Cache-Control':'no-cache',
    }
    if extra_headers: headers.update(extra_headers)  # v30: нужен шлюзам чтения Telegram (например, X-Return-Format у r.jina.ai)
    log(f'HTTP START url={url} timeout={timeout}')
    for attempt in range(2):
        try:
            req=urllib.request.Request(url,headers=headers)
            with urllib.request.urlopen(req,timeout=timeout) as r:
                data=r.read()
                log(f'HTTP urllib OK url={url} status={getattr(r,"status","?")} bytes={len(data)}')
                if data: return data.decode('utf-8','replace')
                raise RuntimeError('empty response')
        except Exception as e:
            msg=f'urllib attempt={attempt+1}: {type(e).__name__}: {e}'
            errors.append(msg); log(f'HTTP FAIL {msg}')
            if attempt==0: time.sleep(0.3)
    if sys.platform=='win32':
        curl=shutil.which('curl.exe') or shutil.which('curl')
        log(f'curl lookup: {curl!r}')
        if curl:
            try:
                extra_h=[x for k,v in (extra_headers or {}).items() for x in ('-H',f'{k}: {v}')]
                cp=subprocess.run([curl,'-L','--fail','--silent','--show-error','--max-time',str(max(5,int(timeout))),'-A',headers['User-Agent'],'-H','Accept: '+headers['Accept'],*extra_h,'--compressed',url],
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout+3,
                                   creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                stderr=_decode_console_bytes(cp.stderr).strip()
                log(f'HTTP curl exit={cp.returncode} bytes={len(cp.stdout)} stderr={stderr[:1000]}')
                if cp.returncode==0 and cp.stdout: return cp.stdout.decode('utf-8','replace')
                errors.append('curl: '+(stderr or ('exit '+str(cp.returncode))))
            except Exception as e:
                msg=f'curl: {type(e).__name__}: {e}'; errors.append(msg); log(f'HTTP FAIL {msg}', True)
        else:
            errors.append('curl: executable not found')
            log('curl executable not found')
        try:
            ps='[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $ProgressPreference="SilentlyContinue"; $r=Invoke-WebRequest -UseBasicParsing -Headers @{"User-Agent"="%s"} -Uri "%s" -TimeoutSec %d; [Console]::Out.Write($r.Content)' % (
                headers['User-Agent'].replace('"','`"'),url.replace('"','`"'),max(5,int(timeout)))
            cp=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',ps],
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout+5,
                               creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            stderr=_decode_console_bytes(cp.stderr).strip()
            log(f'HTTP powershell exit={cp.returncode} bytes={len(cp.stdout)} stderr={stderr[:1000]}')
            if cp.returncode==0 and cp.stdout: return cp.stdout.decode('utf-8','replace')
            errors.append('powershell: '+(stderr or ('exit '+str(cp.returncode))))
        except Exception as e:
            msg=f'powershell: {type(e).__name__}: {e}'; errors.append(msg); log(f'HTTP FAIL {msg}', True)
    err=' | '.join(errors[-6:])
    log(f'HTTP FINAL FAIL url={url}: {err}')
    raise RuntimeError(err)


def _subprocess_kwargs():
    """creationflags=CREATE_NO_WINDOW подавляет мелькание консольного окна у curl/
    powershell на Windows — но на POSIX subprocess.Popen вообще не принимает такой
    именованный аргумент (TypeError), поэтому раньше это было безопасно только потому,
    что вызывалось исключительно внутри `if sys.platform=='win32':` (см. http_get выше).
    Новым прокси-функциям ниже curl нужен НЕ только на Windows (в отличие от http_get,
    где curl — последний резервный способ, здесь он основной способ использовать SOCKS5/
    HTTP-прокси, которого нет у urllib без стороннего пакета) — поэтому вынесено в
    отдельный хелпер, который просто ничего не добавляет на не-Windows."""
    return {'creationflags':subprocess.CREATE_NO_WINDOW} if sys.platform=='win32' else {}


def _build_curl_proxy_arg(proxy):
    """Строит значение для curl --proxy из прокси-словаря пользователя (настройка
    «Рабочий прокси для Telegram-источников», пункт №1 обращения v29). Возвращает None,
    если этот конкретный тип прокси технически не может пересылать произвольный
    HTTPS-трафик — см. большой комментарий у http_get_via_proxy ниже про то, почему
    MTProto/WEB сюда не годятся, только SOCKS5/HTTP."""
    ptype=(proxy or {}).get('ptype')
    if ptype not in ('socks5','http'): return None
    auth=''
    if proxy.get('user'):
        auth=f"{urllib.parse.quote(proxy['user'],safe='')}:{urllib.parse.quote(proxy.get('password') or '',safe='')}@"
    if ptype=='socks5':
        # socks5h (а не просто socks5): резолвит имя хоста ЧЕРЕЗ сам прокси, а не
        # локально — важно именно в нашем сценарии, когда t.me заблокирован похоже на
        # DNS/SNI-уровне: локальный DNS-запрос к t.me может сам быть частью блокировки.
        return f"socks5h://{auth}{proxy['server']}:{proxy['port']}"
    return f"http://{auth}{proxy['server']}:{proxy['port']}"


def http_get_via_proxy(url, timeout, proxy):
    """Как http_get(), но маршрутизирует запрос через указанный пользователем «рабочий
    прокси» (настройка в UI) — используется ТОЛЬКО для доменов Telegram (t.me), которые
    могут быть заблокированы на сети пользователя напрямую (см. tme_reachable,
    fetch_telegram_channel_text). Пункт №1 обращения v29: "подключение к telegram можно
    осуществлять через рабочий прокси... касается всех telegram источников".

    ВАЖНОЕ ТЕХНИЧЕСКОЕ ОГРАНИЧЕНИЕ (честно, без притворства): MTProto-прокси умеет
    пересылать только сам протокол Telegram (MTProto) непосредственно до серверов
    Telegram — он НЕ является прокси общего назначения и physически не может
    переслать произвольный HTTPS-запрос вроде https://t.me/s/канал (это обычная
    веб-страница, а не MTProto-трафик). То же касается WEB-прокси (tg://webproxy) —
    у него тоже нет произвольной пересылки, только TLS+HTTP до его собственного
    сервера-моста. Поэтому если `proxy['ptype']` не 'socks5'/'http',
    _build_curl_proxy_arg() вернёт None и эта функция просто откатывается на обычный
    http_get() без прокси — ВМЕСТО того чтобы молча притворяться, что прокси
    использован. Вызывающий код (scan()) отдельно один раз логирует/предупреждает,
    если пользователь ввёл именно MTProto/нераспознанную строку, чтобы это не терялось.

    Если прокси подходящего типа — пробуются (1) urllib с ProxyHandler (быстро, без
    подпроцесса, но только для HTTP-прокси: сам urllib не умеет SOCKS5 без стороннего
    pysocks, который не добавлен в зависимости проекта специально, чтобы не плодить
    pip-пакеты ради того, что curl и так умеет "из коробки"), затем (2) curl --proxy
    (умеет и SOCKS5, и HTTP; доступен на Windows 10/11 по умолчанию, как и везде в
    http_get). В отличие от http_get, здесь curl пробуется НЕ только на Windows — тут
    это основной рабочий способ, а не last-resort фолбэк."""
    curl_proxy=_build_curl_proxy_arg(proxy)
    if not curl_proxy:
        return http_get(url, timeout)
    errors=[]
    headers={
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36',
        'Accept':'text/plain,application/json,text/html,*/*',
        'Accept-Language':'en-US,en;q=0.9',
        'Cache-Control':'no-cache',
    }
    if proxy.get('ptype')=='http':
        try:
            auth=''
            if proxy.get('user'):
                auth=f"{urllib.parse.quote(proxy['user'],safe='')}:{urllib.parse.quote(proxy.get('password') or '',safe='')}@"
            proxy_url=f"http://{auth}{proxy['server']}:{proxy['port']}"
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({'http':proxy_url,'https':proxy_url}))
            req=urllib.request.Request(url,headers=headers)
            with opener.open(req,timeout=timeout) as r:
                data=r.read()
                if data: return data.decode('utf-8','replace')
                raise RuntimeError('empty response')
        except Exception as e:
            msg=f'urllib+proxy: {type(e).__name__}: {e}'; errors.append(msg); log(f'HTTP(proxy) FAIL {msg}')
    curl=shutil.which('curl.exe') or shutil.which('curl')
    if curl:
        try:
            cp=subprocess.run([curl,'-L','--fail','--silent','--show-error','--max-time',str(max(5,int(timeout))),
                                '-A',headers['User-Agent'],'-H','Accept: '+headers['Accept'],'--compressed',
                                '--proxy',curl_proxy,url],
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout+3,**_subprocess_kwargs())
            stderr=_decode_console_bytes(cp.stderr).strip()
            log(f'HTTP(proxy) curl exit={cp.returncode} bytes={len(cp.stdout)} stderr={stderr[:1000]}')
            if cp.returncode==0 and cp.stdout: return cp.stdout.decode('utf-8','replace')
            errors.append('curl+proxy: '+(stderr or ('exit '+str(cp.returncode))))
        except Exception as e:
            msg=f'curl+proxy: {type(e).__name__}: {e}'; errors.append(msg); log(f'HTTP(proxy) FAIL {msg}', True)
    else:
        errors.append('curl+proxy: executable not found (нужен, чтобы использовать SOCKS5/HTTP-прокси)')
        log('HTTP(proxy) curl executable not found')
    err=' | '.join(errors[-6:])
    log(f'HTTP(proxy) FINAL FAIL url={url} proxy={proxy["server"]}:{proxy["port"]}: {err}')
    raise RuntimeError(err)


def _pkey(p):
    """Единый ключ дедупликации прокси независимо от типа (раньше код в нескольких
    местах вручную собирал ключ как (server,port,secret) — это работало только для
    MTProto; теперь прокси бывают разных типов (см. ptype — 'mtproto'/'socks5'/'http'/
    'web', пункт №1 из обращения пользователя про "другие виды прокси"), поэтому тип
    тоже часть ключа (иначе mtproto-прокси на server:port могла бы "схлопнуться" с
    несвязанной socks5-записью на том же server:port) — а секрет/логин с паролем
    используются как третий компонент, когда они есть."""
    ident=(p.get('secret') or p.get('user') or '').lower()
    return (p.get('ptype','mtproto'), p['server'].lower(), p['port'], ident)


def parse_proxy_link(link):
    try:
        u=urllib.parse.urlparse(link.strip()); q=urllib.parse.parse_qs(u.query)
        server=q.get('server',[None])[0]; port=int(q.get('port',['0'])[0]); secret=q.get('secret',[None])[0]
        if server and 1<=port<=65535 and secret:
            return {'server':server,'port':port,'secret':secret,'ptype':'mtproto',
                    'link':f"tg://proxy?server={urllib.parse.quote(server)}&port={port}&secret={urllib.parse.quote(secret)}"}
    except Exception: pass
    return None


# "Другие виды прокси" (пункт №1 обращения): SOCKS5 и HTTP распознаются по явной схеме
# в ссылке (socks5://..., http://...), с опциональной авторизацией user:pass@ — как в
# тексте сообщений тг-каналов (parse_proxies, когда include_other=True), так и в
# отдельных готовых списках одного типа (parse_typed_links — см. OTHER_PROXY_SOURCES).
# ИСПРАВЛЕНО по следующему обращению пользователя: SOCKS5 иногда публикуют не как
# "socks5://host:port", а как готовую tg-ссылку "tg://socks?server=...&port=..."
# (подтверждено реальным источником kort0881/telegram-proxy-collector) — теперь это
# тоже разбирается, см. TG_SOCKS_RE ниже.
# WEB-прокси — отдельная история: пользователь нашёл и прислал реальную рабочую ссылку
# подключения "tg://webproxy?server=...&secret=..." (её формат подтверждён и официальным
# репозиторием telegramdesktop/tproxy-server — см. README там и комментарий у
# _check_web_proxy). Важно: это НЕ host:port-прокси как socks5/http — у WEB-прокси нет
# порта (всегда 443/HTTPS) и нет user:pass, зато есть server+secret — структурно это
# ближе к MTProto-ссылке (tg://proxy?server=...&secret=...), чем к socks5/http. Поэтому
# WEB разбирается отдельной функцией parse_webproxy_link, а НЕ через _TYPED_LINK_RE_TMPL/
# _make_typed_proxy (которые рассчитаны именно на host:port-прокси).

def parse_socks_tg_link(link):
    """tg://socks?server=...&port=...[&user=...&pass=...] (или https://t.me/socks?...) —
    готовая ссылка подключения SOCKS5, как её публикует, например,
    kort0881/telegram-proxy-collector (socks5.txt) — в отличие от "сырого"
    socks5://host:port, который разбирает _TYPED_LINK_RE_TMPL."""
    try:
        u=urllib.parse.urlparse(link.strip()); q=urllib.parse.parse_qs(u.query)
        server=q.get('server',[None])[0]; port=q.get('port',['0'])[0]
        user=q.get('user',[None])[0]; pwd=q.get('pass',[None])[0]
        return _make_typed_proxy(server,port,'socks5',user,pwd) if server else None
    except Exception:
        return None

def parse_webproxy_link(link):
    """tg://webproxy?server=...&secret=... (или https://t.me/webproxy?...) — реальная
    ссылка подключения WEB-прокси, найденная пользователем и подтверждённая при
    исследовании (формат из README telegramdesktop/tproxy-server: "Share link:
    https://t.me/webproxy?server=HOST&secret=HEX, tg://webproxy эквивалентна"). Порт
    всегда 443 (HTTPS) — это часть самого типа прокси, в ссылке порта нет."""
    try:
        u=urllib.parse.urlparse(link.strip()); q=urllib.parse.parse_qs(u.query)
        server=q.get('server',[None])[0]; secret=q.get('secret',[None])[0]
        if server and secret:
            return {'server':server,'port':443,'secret':secret,'ptype':'web',
                     'link':f"tg://webproxy?server={urllib.parse.quote(server)}&secret={urllib.parse.quote(secret)}"}
    except Exception:
        pass
    return None
_TYPED_LINK_RE_TMPL=r'(?:{scheme}://)?(?:([^:@/\s]{{1,64}}):([^@/\s]{{0,64}})@)?([a-zA-Z0-9\.\-]{{3,255}}):(\d{{2,5}})'

def _make_typed_proxy(host,port,ptype,user=None,pwd=None):
    try: port=int(port)
    except Exception: return None
    if not (1<=port<=65535): return None
    p={'server':host,'port':port,'ptype':ptype,'secret':''}
    if user:
        p['user']=user; p['password']=pwd or ''
    if ptype=='socks5':
        link=f"tg://socks?server={urllib.parse.quote(host)}&port={port}"
        if user: link+=f"&user={urllib.parse.quote(user)}&pass={urllib.parse.quote(pwd or '')}"
        p['link']=link
    else:
        p['link']=(f"{ptype}://{user}:{pwd or ''}@{host}:{port}" if user else f"{ptype}://{host}:{port}")
    return p

def parse_typed_links(text,ptype):
    """Разбирает список прокси ОДНОГО известного типа ('socks5'/'http'/'web') —
    одна ссылка на строку, со схемой (socks5://host:port) или без (host:port), с
    опциональной авторизацией (user:pass@host:port). Используется для специальных
    источников с уже известным типом (OTHER_PROXY_SOURCES), где не нужно гадать тип по
    содержимому, в отличие от parse_proxies."""
    scheme='http' if ptype=='web' else ptype  # web-списки обычно тоже публикуются как http(s)://host:port
    pat=re.compile('^'+_TYPED_LINK_RE_TMPL.format(scheme=scheme)+r'\s*$')
    out={}
    for line in text.splitlines():
        line=line.strip().strip(',')
        if not line or line.startswith('#') or line.startswith('--'): continue
        m=pat.match(line)
        if not m: continue
        user,pwd,host,port=m.groups()
        p=_make_typed_proxy(host,port,ptype,user,pwd)
        if p: out[_pkey(p)]=p
    return list(out.values())


def parse_proxies(text,include_other=False,types=None):
    """Разбирает ссылки прокси из произвольного текста. `types` (v30) — набор видов,
    которые нужно распознавать ('mtproto'/'socks5'/'http'/'web'); невыбранные виды
    пропускаются. Если `types` не задан — прежнее поведение: всегда MTProto, а при
    include_other=True ещё SOCKS5/HTTP/WEB."""
    if types is None:
        want={'mtproto'}|({'socks5','http','web'} if include_other else set())
    else:
        want=set(normalize_types(types))
    out={}
    if 'mtproto' in want:
        for m in TG_RE.finditer(text):
            p=parse_proxy_link(m.group(0).rstrip('.,);'))
            if p: out[_pkey(p)]=p
        for m in re.finditer(r'\{[^{}]{0,1500}\}',text):
            try:
                o=json.loads(m.group(0))
                if all(k in o for k in ('server','port','secret')):
                    p=parse_proxy_link('tg://proxy?server='+urllib.parse.quote(str(o['server']))+'&port='+str(int(o['port']))+'&secret='+urllib.parse.quote(str(o['secret'])))
                    if p: out[_pkey(p)]=p
            except Exception: pass
        # Common plain formats: host:port:secret or host port secret
        for line in text.splitlines():
            line=line.strip().strip(',')
            m=re.match(r'^(?:mtproto://)?([^\s:]+):(\d{2,5}):([0-9a-fA-F]{16,})$',line)
            if m:
                p=parse_proxy_link(f'tg://proxy?server={urllib.parse.quote(m.group(1))}&port={m.group(2)}&secret={m.group(3)}')
                if p: out[_pkey(p)]=p
    if want&{'socks5','http'}:
        # Инлайновые socks5://.../http://... ссылки прямо в тексте (например, в
        # сообщении тг-канала вперемешку с обычными mtproto-ссылками) — только по явной
        # схеме-протоколу (finditer по всему тексту безопасен именно поэтому: ищем
        # конкретную подстроку "socks5://"/"http://", а не голый host:port где угодно).
        for scheme,ptype in (('socks5','socks5'),('http','http'),('https','http')):
            if ptype not in want: continue
            for m in re.finditer(scheme+r'://(?:([^:@/\s]{1,64}):([^@/\s]{0,64})@)?([a-zA-Z0-9\.\-]{3,255}):(\d{2,5})',text,re.I):
                user,pwd,host,port=m.groups()
                p=_make_typed_proxy(host,port,ptype,user,pwd)
                if p: out[_pkey(p)]=p
    if 'socks5' in want:
        # Готовые tg://socks ссылки (см. parse_socks_tg_link).
        for m in TG_SOCKS_RE.finditer(text):
            p=parse_socks_tg_link(m.group(0).rstrip('.,);'))
            if p: out[_pkey(p)]=p
    if 'web' in want:
        for m in TG_WEBPROXY_RE.finditer(text):
            p=parse_webproxy_link(m.group(0).rstrip('.,);'))
            if p: out[_pkey(p)]=p
    return list(out.values())


def parse_single_proxy_input(text):
    """Разбирает ОДНУ запись «рабочего прокси», введённую пользователем в настройке
    «Рабочий прокси для Telegram-источников» (пункт №1 обращения v29). Принимает любой
    уже поддерживаемый программой формат ссылки: tg://proxy?server=...&port=...&secret=
    ... (MTProto — технически не подходит для пересылки t.me-страниц, см. комментарий у
    http_get_via_proxy, но распознаётся честно, а не как ошибка формата), tg://socks?
    server=...&port=... (SOCKS5), socks5://[логин:пароль@]хост:порт,
    http(s)://[логин:пароль@]хост:порт, либо просто "хост:порт" без схемы — такая
    голая запись трактуется как SOCKS5 (самый типичный формат для универсального
    прокси). Возвращает прокси-словарь (с 'ptype') или None, если строка пустая/не
    распознана ни в одном из форматов."""
    text=(text or '').strip()
    if not text: return None
    found=parse_proxies(text, include_other=True)
    if found: return found[0]
    m=re.match(r'^(?:([^:@/\s]{1,64}):([^@/\s]{0,64})@)?([a-zA-Z0-9\.\-]{3,255}):(\d{2,5})$', text)
    if m:
        user,pwd,host,port=m.groups()
        return _make_typed_proxy(host,port,'socks5',user,pwd)
    return None


def fast_probe_get(url, timeout=4.0, max_bytes=262144, headers=None):
    """Single-attempt, no-retry, no-subprocess-fallback fetch used ONLY to probe
    discovery candidates, most of which are expected to 404/fail (that's normal: we're
    guessing filenames/repos). http_get()'s 2-attempt-with-sleep + curl/powershell
    subprocess fallback chain is deliberately thorough (needed for the final, already-
    known-good sources loaded during the actual scan) but far too slow to run on
    hundreds of speculative candidate probes — that chain was the main reason dynamic
    discovery used to take minutes. This helper never raises; it returns None on any
    failure so callers can just treat that as "not a real source".

    `max_bytes` defaults to a small 256KB chunk — plenty to count `secret=`/`t.me/proxy`
    markers in a proxy-list candidate, no need for the whole file. IMPORTANT: callers that
    expect a full, parseable JSON/text document (e.g. the GitHub search API response,
    which can exceed 256KB once per_page=100) MUST pass a larger `max_bytes`, otherwise the
    read is silently truncated mid-document and json.loads() fails on every such call —
    this previously caused several GitHub search queries to fail on every single run."""
    try:
        req=urllib.request.Request(url,headers={
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36',
            'Accept':'text/plain,application/json,text/html,*/*',
            'Accept-Language':'en-US,en;q=0.9',
            **(headers or {}),
        })
        with urllib.request.urlopen(req,timeout=timeout) as r:
            data=r.read(max_bytes)
            return data.decode('utf-8','replace') if data else None
    except Exception:
        return None


def _normalize_discovered_url(url):
    """Map a loosely-specified discovered URL/handle to something actually fetchable.
    Ссылка на тг-канал (t.me/<имя>, t.me/s/<имя>, @имя и их псевдонимы telegram.me/
    telegram.dog/tx.me) превращается в tgchannel://<имя> (v30) — этот псевдо-URL читается
    единым механизмом fetch_telegram_channel_text, который сам выбирает рабочий маршрут
    (прямой t.me / псевдоним домена / шлюз, см. tme_reachable) и листает историю канала.
    Раньше такой кандидат опрашивался прямым запросом к t.me/s/<имя>, то есть вообще не
    работал именно там, где t.me заблокирован."""
    try:
        u=url.strip()
        m=re.match(r'^https?://(?:t\.me|telegram\.me|telegram\.dog|tx\.me)/(?:s/)?(?!proxy|socks|webproxy|joinchat|addstickers)([A-Za-z0-9_]{4,})/?(?:\d+/?)?$', u, re.I)
        if m: return f'tgchannel://{m.group(1)}'
        m=re.match(r'^@([A-Za-z0-9_]{4,})$', u)
        if m: return f'tgchannel://{m.group(1)}'
        return u
    except Exception:
        return url


# ИСПРАВЛЕНО (v28, пункт №1 обращения — "улучшенный поиск всё ещё не ищет тг каналы").
# Анализ нового debug-лога пользователя показал: это не баг в коде и не повторение
# старой проблемы (см. комментарий ниже в fetch_telegram_channel_text про переход на
# http_get в v27) — на этот раз http_get честно логирует КАЖДУЮ попытку, и видно, что
# t.me не отвечает НИ ОДНИМ из 4 способов (2×urllib, curl, powershell) буквально
# каждый раз, с таймаутом ~8с на способ, без единого успеха на протяжении всего лога
# (несколько отдельных запусков сканирования). Такая картина (стабильные ТАЙМАУТЫ на
# ВСЕХ способах, а не быстрые отказы/403) — типичный признак блокировки самого домена
# t.me на уровне сети/провайдера/страны (DPI/SNI), а не проблемы в приложении; это
# достаточно известное явление именно для доменов Telegram в отдельных странах.
# Починить саму блокировку программа не может (это вне её контроля — не прокси-баг),
# но раньше при такой блокировке на КАЖДЫЙ канал впустую тратилось ~30+ секунд (полная
# цепочка http_get: 2×urllib + curl + powershell, все с таймаутом) — умноженное на
# число каналов и число раундов дозапроса это съедало по несколько минут впустую.
# Теперь перед первой попыткой читать канал делается ОДНА быстрая проверка (не полный
# http_get — только чтобы понять "отвечает ли домен вообще"), и если она проваливается,
# все дальнейшие попытки читать тг-каналы в этом сканировании пропускаются сразу, с
# одной понятной строкой в логе — вместо того чтобы домучивать до конца заведомо
# обречённую серию попыток. Результат кешируется на TME_PROBE_TTL секунд: достаточно,
# чтобы не тратить время повторно внутри одного сканирования (в т.ч. между раундами
# дозапроса), но не навсегда — если пользователь включит VPN посреди работы программы
# или в начале следующего сканирования, свежая проверка это заметит (reset_tme_probe_
# cache() дополнительно сбрасывает кеш в начале каждого нового scan()).
TME_PROBE_TTL=120.0

# ---------------------------------------------------------------------------
# v30 (пункт №2 обращения): чтение Telegram-каналов БЕЗ прямого доступа к t.me.
#
# Проблема пользователя: Telegram у него работает ТОЛЬКО через MTProto-прокси, а
# t.me (обычная веб-страница) с его сети недоступен — и «Улучшенный поиск» оставался
# без тг-каналов. Прямой ответ «найти рабочий SOCKS5/HTTP» (v29) таким пользователям не
# подходит: их мало и они сами часто недоступны. А MTProto-прокси технически не может
# пересылать HTTPS (он пропускает только зашифрованный протокол Telegram до его серверов),
# поэтому через найденный MTProto страницу t.me/s/<канал> не открыть — это не обходится.
#
# Что МОЖНО сделать честно — искать обходной МАРШРУТ до тех же публичных страниц каналов
# (t.me/s/<канал>, их читает любой браузер без входа в аккаунт). Программа пробует по
# очереди (параллельно, берёт первый рабочий по приоритету) и запоминает на сканирование:
#   1) t.me напрямую (или через указанный «рабочий прокси» SOCKS5/HTTP);
#   2) свой шлюз пользователя (если задан шаблон в поле «Рабочий прокси…», см.
#      parse_gateway_template);
#   3) официальные псевдонимы домена — telegram.me, telegram.dog, tx.me: блокировка по
#      имени (SNI/DNS) часто бьёт только t.me;
#   4) публичные «шлюзы-читалки» — сторонние сервисы, которые сами скачивают страницу и
#      отдают её нам (r.jina.ai, allorigins, codetabs, corsproxy.io, RSSHub): для сети
#      пользователя это обычный запрос к стороннему сайту, а не к Telegram.
# Ограничения (честно): если заблокированы ВСЕ IP Telegram, пункт 3 не поможет (те же
# адреса); шлюзы — сторонние бесплатные сервисы: могут быть перегружены/недоступны/
# отдать капчу — поэтому КАЖДЫЙ ответ проверяется по содержимому (должны быть настоящие
# посты канала), а не по коду 200. Через шлюз уходит только имя ПУБЛИЧНОГО канала
# (отключается галочкой «Обходить блокировку t.me через публичные шлюзы»). Если ни
# один маршрут не сработал — поиск по каналам честно пропускается, остаются GitHub и сайты.
# ---------------------------------------------------------------------------
TG_ALT_DOMAINS = ('telegram.me', 'telegram.dog', 'tx.me')
TG_GATEWAYS = [
    # (имя, вид, шаблон, доп. заголовки). {url}/{urlenc} — целевая страница, {ch} — канал.
    ('r.jina.ai', 'wrap', 'https://r.jina.ai/{url}', {'X-Return-Format': 'html'}),
    ('allorigins', 'wrap', 'https://api.allorigins.win/raw?url={urlenc}', None),
    ('codetabs', 'wrap', 'https://api.codetabs.com/v1/proxy/?quest={urlenc}', None),
    ('corsproxy.io', 'wrap', 'https://corsproxy.io/?url={urlenc}', None),
    ('RSSHub', 'rss', 'https://rsshub.app/telegram/channel/{ch}', None),
]
TG_PROBE_CHANNEL = 'telegram'   # официальный канал Telegram — гарантированно существует и публичен
_TG_ACCESS = {'proxy': None, 'gateway': None, 'use_gateways': True}
_TME_PROBE_CACHE = {'ok': None, 'ts': 0.0, 'route': None, 'trace': ''}

def reset_tme_probe_cache():
    _TME_PROBE_CACHE['ok'] = None; _TME_PROBE_CACHE['ts'] = 0.0
    _TME_PROBE_CACHE['route'] = None; _TME_PROBE_CACHE['trace'] = ''

def parse_gateway_template(text):
    """Шаблон своего шлюза из поля «Рабочий прокси для Telegram-источников»: URL со
    вставками {url} (адрес страницы t.me/s/<канал>, как есть), {urlenc} (он же,
    URL-кодированный) или {ch} (имя канала). Пример: https://my.example/fetch?u={urlenc}.
    Возвращает строку-шаблон или None, если это не шаблон."""
    t = (text or '').strip()
    if re.match(r'^https?://', t, re.I) and any(k in t for k in ('{url}', '{urlenc}', '{ch}')):
        return t
    return None

def configure_tg_access(proxy=None, gateway=None, use_gateways=True):
    """Задаёт параметры доступа к Telegram на ближайшее сканирование (вызывается из
    scan()) и сбрасывает кеш маршрута."""
    _TG_ACCESS['proxy'] = proxy; _TG_ACCESS['gateway'] = gateway; _TG_ACCESS['use_gateways'] = bool(use_gateways)
    reset_tme_probe_cache()

def build_tg_routes(proxy=None, gateway=None, use_gateways=True):
    """Упорядоченный список маршрутов чтения t.me/s/<канал> (см. описание выше)."""
    px = proxy if (proxy and _build_curl_proxy_arg(proxy)) else None
    routes = [{'name': 't.me через рабочий прокси' if px else 't.me', 'kind': 'direct', 'domain': 't.me', 'proxy': px, 'tpl': None, 'headers': None}]
    if gateway:
        kind = 'rss' if ('{ch}' in gateway and '{url' not in gateway) else 'wrap'
        routes.append({'name': 'свой шлюз', 'kind': kind, 'domain': 't.me', 'proxy': None, 'tpl': gateway, 'headers': None})
    for d in TG_ALT_DOMAINS:
        routes.append({'name': d, 'kind': 'direct', 'domain': d, 'proxy': px, 'tpl': None, 'headers': None})
    if use_gateways:
        for name, kind, tpl, hdrs in TG_GATEWAYS:
            routes.append({'name': name, 'kind': kind, 'domain': 't.me', 'proxy': None, 'tpl': tpl, 'headers': hdrs})
    return routes

def _route_url(route, channel, before=None):
    target = f"https://{route['domain']}/s/{channel}" + (f'?before={before}' if before else '')
    if route['kind'] == 'direct': return target
    tpl = route['tpl']
    if route['kind'] == 'rss': return tpl.replace('{ch}', channel)
    return tpl.replace('{urlenc}', urllib.parse.quote(target, safe='')).replace('{url}', target).replace('{ch}', channel)

def _looks_like_channel_page(text, channel):
    """Ответ — настоящая страница/лента канала (а не заглушка провайдера, капча или
    JSON-ошибка шлюза): есть разметка постов t.me либо ссылки вида <канал>/<id поста>."""
    if not text: return False
    return ('tgme_widget_message' in text) or bool(re.search(re.escape(channel)+r'/\d+', text))

def _route_get(route, channel, before, timeout):
    """Полная загрузка одной страницы выбранным маршрутом (с надёжными повторами http_get)."""
    url = _route_url(route, channel, before)
    if route['kind'] == 'direct':
        if route.get('proxy') and _build_curl_proxy_arg(route['proxy']):
            return http_get_via_proxy(url, timeout, route['proxy'])
        return http_get(url, timeout)
    if route.get('headers'):
        return http_get(url, timeout, extra_headers=route['headers'])
    return http_get(url, timeout)

def _route_probe_one(route, timeout):
    """Быстрая однопопыточная проверка маршрута на канале TG_PROBE_CHANNEL; True только
    если вернулись настоящие посты. Никогда не бросает исключений."""
    try:
        url = _route_url(route, TG_PROBE_CHANNEL, None)
        if route['kind'] == 'direct' and route.get('proxy') and _build_curl_proxy_arg(route['proxy']):
            text = http_get_via_proxy(url, timeout, route['proxy'])
        elif route.get('headers'):
            text = fast_probe_get(url, timeout, max_bytes=300000, headers=route['headers'])
        else:
            text = fast_probe_get(url, timeout, max_bytes=300000)
        return _looks_like_channel_page(text, TG_PROBE_CHANNEL)
    except Exception:
        return False

def probe_tg_routes(routes, timeout=3.0, gateway_timeout=6.0):
    """Проверяет все маршруты ПАРАЛЛЕЛЬНО и возвращает (первый_рабочий_по_приоритету |
    None, трасса). Если рабочий — прямой t.me, ответ приходит за один круг сети, не
    дожидаясь медленных шлюзов."""
    if not routes: return None, []
    ex = ThreadPoolExecutor(max_workers=len(routes))
    try:
        futs = [ex.submit(_route_probe_one, r, timeout if r['kind'] == 'direct' else gateway_timeout) for r in routes]
        deadline = time.time() + gateway_timeout + 1.0
        trace = []
        for r, f in zip(routes, futs):
            try: ok = bool(f.result(timeout=max(0.1, deadline - time.time())))
            except Exception: ok = False
            trace.append(f"{r['name']}={'ok' if ok else 'нет'}")
            if ok: return r, trace
        return None, trace
    finally:
        ex.shutdown(wait=False, cancel_futures=True)

def tme_reachable(timeout=3.0, proxy=None):
    """Есть ли хоть один рабочий маршрут чтения тг-каналов (см. описание выше). Результат
    (и выбранный маршрут) кешируется на TME_PROBE_TTL секунд и сбрасывается в начале
    каждого сканирования (reset_tme_probe_cache). `proxy` — рабочий SOCKS5/HTTP-прокси
    (если не задан, берётся из configure_tg_access)."""
    now = time.time()
    if _TME_PROBE_CACHE['ok'] is not None and (now - _TME_PROBE_CACHE['ts']) < TME_PROBE_TTL:
        return _TME_PROBE_CACHE['ok']
    px = proxy if proxy is not None else _TG_ACCESS['proxy']
    routes = build_tg_routes(px, _TG_ACCESS['gateway'], _TG_ACCESS['use_gateways'])
    route, trace = probe_tg_routes(routes, timeout)
    ok = route is not None
    _TME_PROBE_CACHE.update(ok=ok, ts=now, route=route, trace=', '.join(trace))
    if ok:
        log(f"TME PROBE OK: чтение тг-каналов через «{route['name']}» (проверено: {', '.join(trace)})")
    else:
        log(f"TME PROBE FAIL: ни один маршрут чтения тг-каналов не сработал ({', '.join(trace)}) — похоже на блокировку Telegram на уровне сети/страны или временную недоступность; поиск по тг-каналам пропускается на ближайшие {TME_PROBE_TTL:.0f}с, остаются GitHub и сайты")
    return ok

def describe_tg_access():
    """Короткая человекочитаемая строка для статуса: каким путём читаются тг-каналы."""
    if _TME_PROBE_CACHE['ok'] is None: return ''
    if _TME_PROBE_CACHE['ok']:
        r = _TME_PROBE_CACHE.get('route') or {}
        return f"Telegram-каналы читаются через: {r.get('name', 't.me')}"
    return 'Telegram-каналы недоступны ни одним маршрутом — ищем по GitHub и сайтам'


def fetch_telegram_channel_text(channel, max_messages=TELEGRAM_CHANNEL_MESSAGE_LIMIT, stop_event=None, timeout=7.0, proxy=None):
    """Скачивает текст последних `max_messages` сообщений ОТКРЫТОГО (публичного)
    Telegram-канала через его статическую веб-версию (t.me/s/<channel>) — доступно
    без входа в Telegram, так же, как в обычном браузере (пункты №2 и №3 обращения
    пользователя). Канал отдаёт посты порциями (обычно ~20-25 за раз); более старые
    листаются параметром ?before=<id самого старого полученного поста> — ровно так
    же, как работает кнопка "Load more" на самой странице. Останавливается, когда
    набрано достаточно сообщений, кончилась история (новых id на странице не
    появилось) или достигнут TELEGRAM_CHANNEL_MAX_PAGES (защита от зацикливания).

    Возвращает (text, linked_files):
      text          — сырой текст всех собранных страниц одним блоком (его разбирает
                      parse_proxies, как и любой другой источник — ищет и
                      tg://proxy/t.me/proxy ссылки, вставленные прямо в сообщения).
      linked_files  — список прямых http(s)-ссылок на .txt/.json, встреченных в
                      тексте сообщений (например, кто-то выложил ссылку на свой
                      файл-список на GitHub/собственном сайте прямо в посте) — их
                      тоже стоит скачать как источник, см. _load_channel_source.

    ВАЖНОЕ ОГРАНИЧЕНИЕ (честно, без притворства): если прокси в канале не вставлены
    прямыми ссылками в текст, а приложены как настоящий файл-вложение Telegram (как
    это иногда делают боты — см. обращение, пункт №3), содержимое такого вложения
    НЕДОСТУПНО через публичную веб-версию — его может скачать только сам клиент
    Telegram (нужен вход в аккаунт/Bot API). Такие вложения только отмечаются в логе
    (видно имя файла), чтобы это не терялось молча, но не скачиваются.

    `proxy` (пункт №1 обращения v29) — если задан рабочий SOCKS5/HTTP-прокси, ВСЕ
    обращения к t.me (включая саму проверку доступности) идут через него — см.
    tme_reachable/http_get_via_proxy. MTProto-/WEB-прокси технически не подходят для
    этого (см. http_get_via_proxy) — тогда функция ведёт себя так, будто proxy не
    задан."""
    if not tme_reachable(proxy=proxy):
        return '',[]
    # v30: выбранный при проверке маршрут (прямой t.me / псевдоним домена / шлюз). Если
    # кеша маршрута нет (проверка подменена, как в тестах) — обычный прямой t.me.
    route=_TME_PROBE_CACHE.get('route') or {'name':'t.me','kind':'direct','domain':'t.me','proxy':proxy if (proxy and _build_curl_proxy_arg(proxy)) else None,'tpl':None,'headers':None}
    collected=[]; seen_ids=set(); before=None; pages=0
    while len(seen_ids)<max_messages and pages<TELEGRAM_CHANNEL_MAX_PAGES:
        if stop_event is not None and stop_event.is_set(): break
        pages+=1
        url=_route_url(route,channel,before)
        # РЕАЛЬНЫЙ БАГ, пойманный по логу пользователя: раньше здесь использовался
        # fast_probe_get — он намеренно быстрый и МОЛЧА проглатывает любую ошибку (одна
        # попытка urllib, без retry и без curl/powershell-фолбэка), что годится для
        # перебора сотен гипотетических GitHub-кандидатов, но оказалось слишком хрупким
        # именно для t.me: в логе пользователя абсолютно каждый вызов показывал
        # "messages~=0" — то есть сайт ни разу толком не открылся, а почему именно —
        # fast_probe_get даже не логировал. Каналов тут мало (не сотни кандидатов, а
        # фиксированный список из нескольких штук), поэтому используем тот же надёжный
        # http_get, что и для обычных источников (2 попытки urllib + на Windows ещё
        # curl/powershell-фолбэк, который в том же логе успешно вытаскивал другие
        # источники) — и он честно пишет в лог, на каком именно шаге и почему не вышло.
        try:
            page_html=_route_get(route,channel,before,timeout)
        except Exception as e:
            log(f'TGCHAN page FAIL channel={channel} url={url}: {e}')
            page_html=None
        if page_html and len(page_html)>1_500_000: page_html=page_html[:1_500_000]
        if not page_html: break
        collected.append(page_html)
        ids=[int(x) for x in re.findall(re.escape(channel)+r'/(\d+)',page_html)]
        if not ids: break
        if route['kind']=='rss':  # лента RSS — одна порция без листания назад
            seen_ids.update(ids); break
        new_ids=set(ids)-seen_ids
        seen_ids.update(ids)
        if not new_ids: break  # страница не принесла новых id — дальше в истории канала пусто
        oldest=min(ids)
        if before is not None and oldest>=before: break  # защита от зацикливания, если сервер не слушает before=
        before=oldest
    # HTML-экранирование (href="...&amp;secret=..." и т.п.) обязательно разворачиваем
    # ДО поиска tg://proxy-ссылок — иначе "&amp;" внутри query-строки ссылки ломает
    # разбор port=/secret= в parse_proxy_link (urllib.parse.parse_qs режет по "&", а
    # "&amp;" содержит свой собственный "&" не на том месте — проверено тестом на
    # синтетической странице, без этого НИ ОДНА ссылка из реальной HTML-страницы
    # канала не разобралась бы, хотя visuально текст выглядит нормально).
    full_text='\n'.join(collected)
    # До трёх раундов: у RSS-лент (маршрут RSSHub) HTML внутри <description> экранирован
    # дважды (XML + HTML), у обычной страницы канала достаточно одного.
    for _ in range(3):
        un=html.unescape(full_text)
        if un==full_text: break
        full_text=un
    for fn in re.findall(r'tgme_widget_message_document_title["\'][^>]*>\s*([^<]{1,200})<',full_text):
        log(f'TGCHAN вложение-файл обнаружено, но недоступно без входа в Telegram (пропущено): channel={channel} file={fn.strip()}')
    linked_files=[]
    for u in re.findall(r'href="(https?://[^"]+?\.(?:txt|json))"',full_text,re.I):
        if u not in linked_files: linked_files.append(u)
    log(f'TGCHAN channel={channel} route={route["name"]} pages={pages} messages~={len(seen_ids)} linked_files={len(linked_files)}')
    return full_text,linked_files


def _load_channel_source(tgchannel_url, include_other=False, proxy=None):
    """Разворачивает псевдо-URL tgchannel://<канал> (см. STATIC_SOURCES/ENHANCED_SEED_
    CHANNELS) в реальный текст: сообщения канала + содержимое всех .txt/.json-файлов,
    на которые в сообщениях нашлись прямые ссылки (но не настоящие Telegram-вложения —
    см. ограничение в fetch_telegram_channel_text). Возвращает единый текстовый блок,
    который дальше разбирает parse_proxies — так же, как при обычной загрузке
    источника по http_get.

    `proxy` — рабочий прокси (пункт №1 обращения v29) для самого чтения канала (t.me);
    найденные внутри сообщений ссылки на .txt/.json-файлы — произвольные сайты, не
    t.me, поэтому грузятся как обычно, напрямую, без прокси."""
    channel=tgchannel_url[len('tgchannel://'):]
    text,linked_files=fetch_telegram_channel_text(channel, proxy=proxy)
    parts=[text]
    for fu in linked_files[:10]:  # разумный предел — не тащить десятки вложенных файлов за один источник
        try: parts.append(http_get(fu,8))
        except Exception as e: log(f'TGCHAN linked file FAIL channel={channel} url={fu}: {e}')
    return '\n'.join(parts)


def _interruptible_sleep(stop_event, seconds):
    """time.sleep() that wakes up early if the scan is stopped, so a backoff pause
    between discovery retry attempts never makes the "Остановить" button feel stuck."""
    end=time.time()+max(0.0,seconds)
    while time.time()<end:
        if stop_event.is_set(): return
        time.sleep(min(0.2,max(0.0,end-time.time())))


def _github_search_once(q, timeout, github_token=None):
    """One raw GitHub repo-search request, bypassing fast_probe_get's broad exception
    swallow so a rate-limit response (HTTP 403/429 — the unauthenticated Search API is
    capped at roughly 10 requests/minute total across ALL queries) can be told apart from
    a genuine network failure or truly-empty result. Returns (items, reason) where reason
    is None on success or a short tag ('rate_limited', 'http_404', 'URLError', ...) on
    failure — discover_sources() uses this to decide whether retrying later is worth it,
    instead of silently treating "rate-limited" and "no results at all" the same way (which
    is what made search look random and finish early regardless of the time budget).

    `github_token` (пункт №2 обращения v28 — "лимит GitHub API ужасно раздражает"):
    единственный ЧЕСТНЫЙ способ обойти этот лимит — не обходной трюк, а настоящая
    аутентификация. У GitHub Search API лимит без входа — ~10 запросов/мин ОБЩИЙ на всех
    пользователей интернета сразу (отсюда и жалоба — он делится не только между
    раундами дозапроса одного пользователя, а вообще со всеми); с личным токеном
    (Personal Access Token, без каких-либо прав/scope — токен нужен только для того,
    чтобы запрос засчитался «от конкретного аккаунта», а не анонимно) лимит поднимается
    примерно до 30 запросов/мин — втрое. Токен необязателен (поле в настройках
    «GitHub token»); если его нет, поведение не меняется — ровно как просил
    пользователь ("если обойти не получится, оставим как есть")."""
    url=('https://api.github.com/search/repositories?q='+urllib.parse.quote(q)+
         '&sort=updated&order=desc&per_page=100')
    try:
        headers={
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36',
            'Accept':'application/vnd.github+json',
        }
        if github_token:
            headers['Authorization']='token '+github_token
        req=urllib.request.Request(url,headers=headers)
        with urllib.request.urlopen(req,timeout=timeout) as r:
            data=r.read(3_000_000)  # см. комментарий у fast_probe_get про обрезание при per_page=100
        return json.loads(data.decode('utf-8','replace')).get('items',[]), None
    except urllib.error.HTTPError as e:
        return [], ('rate_limited' if e.code in (403,429) else f'http_{e.code}')
    except Exception as e:
        return [], type(e).__name__


def _ddg_search_urls(query, max_results=6, timeout=4.0):
    """Best-effort DuckDuckGo HTML scrape (no API key needed) returning candidate result
    URLs for a query. Used only by Улучшенный поиск to find Telegram channels/websites/
    forums beyond the fixed seed list — i.e. actual searching, not just a hardcoded list.
    Never raises; returns [] on any failure (network blocked, markup changed, etc.)."""
    try:
        text=fast_probe_get('https://html.duckduckgo.com/html/?q='+urllib.parse.quote(query), timeout)
        if not text: return []
        out=[]
        for enc in re.findall(r'uddg=([^"&]+)', text):
            try:
                real=urllib.parse.unquote(enc)
            except Exception:
                continue
            if real.startswith('http') and real not in out:
                out.append(real)
            if len(out)>=max_results: break
        return out
    except Exception:
        return []


def discover_sources(stop_event, status_cb, target=40, enhanced=False, exclude=frozenset(), time_budget=None, github_token=None, telegram_proxy=None, types=None):
    """Discover public sources that publish MTProto proxy lists, at runtime.

    Normal mode (enhanced=False) searches GitHub only: several precise `topic:` and
    free-text queries (incl. Russian/Farsi ones, since much of this ecosystem is
    RU/IR-focused).

    Enhanced mode (enhanced=True) ALSO treats public Telegram channels and proxy-list
    websites/forum pages as sources — both a verified seed list (ENHANCED_SEED_CHANNELS/
    ENHANCED_SEED_WEBSITES) and further pages found via a live DuckDuckGo text search
    (ENHANCED_SEARCH_QUERIES) — on top of everything GitHub-based.

    A candidate is only ever counted as a real source after its CONTENT is actually
    fetched and shown to contain several `secret=`/`t.me/proxy` occurrences — never by
    trusting a filename/URL pattern alone.

    Speed: every candidate across every query/repo/seed/search-hit is collected into one
    list up front and probed in ONE shared thread pool (DISCOVERY_PROBE_WORKERS workers)
    with fast_probe_get (single attempt, short timeout, no subprocess fallback) — not
    sequentially per query/repo like before.

    Retries: a single pass over GitHub's search API is subject to its unauthenticated
    rate limit (~10 requests/minute total) — if that's already exhausted (e.g. the user
    just ran a search a few seconds ago), ALL 11 queries can come back empty almost
    instantly, which used to make the whole function return in under a second regardless
    of how much time was budgeted, with a near-random source count depending on pure
    timing luck. Now, whenever time remains and the target isn't met, the function waits
    out a backoff (longer after a detected rate-limit, since that's the actual bottleneck)
    and tries the GitHub queries again — bounded by MAX_DISCOVERY_INTERNAL_RETRIES as a
    safety cap, but normally bounded simply by running out of `time_budget`. The whole
    function is bounded by a hard wall-clock deadline (DISCOVERY_TIME_BUDGET[_ENHANCED],
    or `time_budget` when given), so a pile of slow/dead hosts — or a GitHub outage — can
    never make the user wait "hours": it simply stops and returns whatever it found.

    `exclude` — a set of raw URLs to skip even if (re-)found — used when scan() calls this
    a second time to top up a short-on-proxies scan with fresh sources, so the top-up round
    doesn't waste its whole time budget re-probing the exact same sources as the first round.

    `github_token` — опциональный личный токен GitHub (настройка «GitHub token»), поднимающий
    лимит Search API с ~10 до ~30 запросов/мин (см. комментарий у _github_search_once). None
    по умолчанию — поведение без токена не меняется.

    `telegram_proxy` — опциональный рабочий SOCKS5/HTTP-прокси (настройка «Рабочий прокси
    для Telegram-источников», пункт №1 обращения v29) для чтения tgchannel:// кандидатов
    (t.me), когда сам t.me недоступен напрямую — см. fetch_telegram_channel_text.

    `types` (v30) — какие виды прокси искать ('mtproto'/'socks5'/'http'/'web'; по умолчанию
    только MTProto, как раньше). Для каждого вида выполняются ТОЛЬКО его запросы GitHub
    (DISCOVERY_QUERIES_BY_TYPE), перебираются ТОЛЬКО его имена файлов
    (COMMON_FILENAMES_BY_TYPE), а кандидат принимается, лишь если по его СОДЕРЖИМОМУ он
    годится хотя бы для одного выбранного вида (sample_matches_type). У принятых «голых»
    списков host:port запоминается тип (_SOURCE_TYPE_HINTS) — по нему scan() разбирает файл
    через parse_typed_links. Запросы GitHub, уже выполненные успешно, повторно не
    отправляются (ответ был бы тем же — это лишь тратило лимит API); повторяются только
    упёршиеся в rate-limit.
    """
    start=time.time()
    types=normalize_types(types) or ('mtproto',)
    if time_budget is None:
        time_budget=DISCOVERY_TIME_BUDGET_ENHANCED if enhanced else DISCOVERY_TIME_BUDGET
    deadline=start+time_budget
    sources=[]; seen_urls=set(exclude); seen_repos=set(); lock=threading.Lock()
    repo_types={}  # репозиторий -> виды, по запросам которых он найден

    def time_left(): return deadline-time.time()

    def try_add(raw_url, label, qtype=None):
        if stop_event.is_set() or time_left()<=0: return False
        with lock:
            if raw_url in seen_urls or len(sources)>=target: return False
            seen_urls.add(raw_url)
        if raw_url.startswith('tgchannel://'):
            # ИСПРАВЛЕНО (пункт №2 обращения — "ни разу не видел, чтобы брала тг каналы"):
            # раньше сюда попадал обычный https://t.me/<channel> — это лендинг канала
            # (название, фото, кнопка «открыть»), а не лента сообщений, поэтому почти
            # никогда не содержал "secret=" и отбраковывался этой же проверкой ниже.
            # Теперь берём настоящий текст последних сообщений через ту же функцию,
            # что и обычная загрузка источников (см. _load_channel_source) — единое
            # место, которое действительно умеет читать сообщения канала (и выбирать
            # рабочий маршрут до него, см. tme_reachable).
            try:
                sample,_=fetch_telegram_channel_text(raw_url[len('tgchannel://'):],
                                                       max_messages=TELEGRAM_CHANNEL_MESSAGE_LIMIT,
                                                       stop_event=stop_event,
                                                       timeout=min(8.0,max(3.0,time_left())),
                                                       proxy=telegram_proxy)
            except Exception:
                sample=None
        else:
            sample=fast_probe_get(raw_url, min(4.0,max(1.5,time_left())))
        if not sample: return False
        # Годится ли содержимое хотя бы для одного ВЫБРАННОГО вида (сначала — вид запроса,
        # по которому кандидата нашли).
        order=([qtype] if qtype in types else [])+[t for t in types if t!=qtype]
        accepted=next((t for t in order if sample_matches_type(sample,t)),None)
        if accepted is None: return False
        hint=None
        if accepted in ('socks5','http') and not sample_matches_type(sample,'mtproto'):
            guess=_guess_list_type(raw_url)
            if guess=='socks4': return False   # SOCKS4 не поддерживается проверкой — не берём
            hint=guess if guess in types else accepted
        with lock:
            if len(sources)>=target: return False
            sources.append((raw_url,label)); n=len(sources)
            if hint: _SOURCE_TYPE_HINTS[raw_url]=hint
        status_cb(f'{"Улучшенный" if enhanced else "Динамический"} поиск источников… найдено {n} из {target}')
        return True

    # Какие запросы GitHub ещё нужно выполнить: (запрос, вид). Успешно выполненные
    # убираются и не повторяются (см. docstring).
    pending_queries=[(q,t) for t in types for q in DISCOVERY_QUERIES_BY_TYPE.get(t,[])]

    probe_pool=ThreadPoolExecutor(max_workers=DISCOVERY_PROBE_WORKERS)
    try:
        attempt=0
        while True:
            attempt+=1
            if stop_event.is_set() or time_left()<=0 or len(sources)>=target: break

            # ---- 1) все (оставшиеся) GitHub-запросы — параллельно, одним пулом ----
            per_query_timeout=min(6.0,max(2.0,time_left()))
            results=list(probe_pool.map(lambda qt:_github_search_once(qt[0],per_query_timeout,github_token), pending_queries))
            new_repos=[]; rate_limited_count=0; still_pending=[]
            for (q,qt),(items,reason) in zip(pending_queries,results):
                if reason: still_pending.append((q,qt))   # rate-limit/сетевой сбой — попробуем снова
                if reason=='rate_limited': rate_limited_count+=1
                for r in items:
                    full=r.get('full_name')
                    if not full: continue
                    repo_types.setdefault(full,[])
                    if qt not in repo_types[full]: repo_types[full].append(qt)
                    if full not in seen_repos:
                        seen_repos.add(full); new_repos.append((full, r.get('default_branch') or 'main'))
            n_queries=len(pending_queries); pending_queries=still_pending
            if rate_limited_count:
                log(f'DISCOVERY github rate-limited on {rate_limited_count}/{n_queries} запросов (попытка {attempt}) — это нормально, не ошибка: подождём и повторим только их')
            log(f'DISCOVERY github repos found={len(new_repos)} (всего уникальных={len(seen_repos)}) attempt={attempt} types={",".join(types)} queries_left={len(pending_queries)} elapsed={time.time()-start:.1f}s')

            # ---- 2) собираем кандидатов ТОЛЬКО из новых репозиториев этой попытки ----
            candidates=[]  # (url, label, вид запроса)
            for full,branch in new_repos:
                b=urllib.parse.quote(branch,safe='')
                paths_seen=set()
                for t in repo_types.get(full,['mtproto']):
                    for path in COMMON_FILENAMES_BY_TYPE.get(t,[]):
                        if path in paths_seen: continue
                        paths_seen.add(path)
                        candidates.append((f'https://raw.githubusercontent.com/{full}/{b}/{path}', full+':'+path, t))
            random.shuffle(candidates)  # не тратим весь дедлайн на первые N репозиториев
            candidates=candidates[:MAX_DISCOVERY_CANDIDATES]

            ddg_failed=False
            if enhanced:
                if attempt==1:  # seed-каналы/сайты не меняются между попытками — добавляем раз
                    for ch in ENHANCED_SEED_CHANNELS:
                        candidates.append((f'tgchannel://{ch}', 'tg:'+ch, None))
                    for site in ENHANCED_SEED_WEBSITES:
                        candidates.append((site, site, None))
                    if time_left()>6:
                        found_urls=[]
                        for urls in probe_pool.map(lambda q:_ddg_search_urls(q,6,min(4.0,time_left())), ENHANCED_SEARCH_QUERIES):
                            found_urls.extend(urls)
                        for u in dict.fromkeys(found_urls):
                            nu=_normalize_discovered_url(u)
                            candidates.append((nu, nu, None))

            # try_add() сам отфильтрует уже проверенные URL через seen_urls, но отсекаем их
            # здесь заранее, чтобы не засорять пул futures заведомо повторными кандидатами
            # между попытками.
            candidates=[c for c in candidates if c[0] not in seen_urls]
            log(f'DISCOVERY candidates built attempt={attempt} count={len(candidates)} total_repos_seen={len(seen_repos)}')

            # ---- 3) пробуем кандидатов этой попытки одним общим пулом, ограничено дедлайном ----
            futures=[]
            for raw,label,qt in candidates:
                if stop_event.is_set() or time_left()<=0 or len(sources)>=target: break
                futures.append(probe_pool.submit(try_add, raw, label, qt))
            try:
                for f in as_completed(futures, timeout=max(1.0,time_left()+3)):
                    if stop_event.is_set() or len(sources)>=target: break
                    try: f.result()
                    except Exception: pass
            except Exception:
                pass  # дедлайн по as_completed() истёк — используем то, что успели найти

            if stop_event.is_set() or len(sources)>=target: break
            if time_left()<=5 or attempt>=MAX_DISCOVERY_INTERNAL_RETRIES: break
            if not pending_queries:
                # Все запросы GitHub выполнены успешно, seed/веб-поиск тоже один раз —
                # повторять нечего (раньше здесь крутился повтор тех же запросов вхолостую).
                log(f'DISCOVERY нечего повторять: все запросы выполнены (attempt={attempt})')
                break

            # Бэкофф перед повторной попыткой: если причиной был rate-limit — ждём дольше
            # (лимит GitHub сбрасывается по скользящему окну примерно за минуту), иначе
            # (сетевой сбой) короткой паузы достаточно.
            backoff=min(time_left()-2, 12.0 if rate_limited_count else 3.0)
            if backoff>0.3:
                status_cb(f'{"Улучшенный" if enhanced else "Динамический"} поиск источников… найдено {len(sources)} из {target}, повтор через {backoff:.0f} с ({"лимит GitHub API" if rate_limited_count else "ищем ещё"})…')
                _interruptible_sleep(stop_event, backoff)
    finally:
        probe_pool.shutdown(wait=False, cancel_futures=True)

    elapsed=time.time()-start
    log(f'DISCOVERY done enhanced={enhanced} types={",".join(types)} found={len(sources)}/{target} elapsed={elapsed:.1f}s attempts={attempt}')
    if len(sources)<target:
        status_cb(f'Поиск источников завершён за {elapsed:.0f} с — найдено {len(sources)} из {target}.')
    return sources


def resolve_ip(host):
    try: return socket.gethostbyname(host)
    except Exception: return None



# Minimal pure-Python AES-256-CTR used for MTProto transport verification.
# This keeps the scanner dependency-free on a normal Python installation.
def _gf_mul(a,b):
    r=0
    for _ in range(8):
        if b&1:r^=a
        hi=a&0x80; a=(a<<1)&0xff
        if hi:a^=0x1b
        b>>=1
    return r

def _rotl8(x,n): return ((x<<n)|(x>>(8-n)))&0xff

def _aes_sbox():
    s=[]
    for x in range(256):
        y=0 if x==0 else pow(x,254,257)  # inverse in GF(2^8) via integer pow is corrected below
        if x:
            # GF inverse by exponentiation using the AES polynomial
            y=1
            a=x; e=254
            while e:
                if e&1:y=_gf_mul(y,a)
                a=_gf_mul(a,a); e>>=1
        s.append(y ^ _rotl8(y,1)^_rotl8(y,2)^_rotl8(y,3)^_rotl8(y,4)^0x63)
    return bytes(s)

_AES_SBOX=_aes_sbox(); _AES_RCON=[1]
for _ in range(1,15): _AES_RCON.append(_gf_mul(_AES_RCON[-1],2))

def _aes_expand(key):
    key=bytes(key); assert len(key)==32
    w=[bytearray(key[i:i+4]) for i in range(0,32,4)]
    for i in range(8,60):
        t=bytearray(w[i-1])
        if i%8==0:
            t=t[1:]+t[:1]; t=bytearray(_AES_SBOX[x] for x in t); t[0]^=_AES_RCON[i//8-1]
        elif i%8==4:
            t=bytearray(_AES_SBOX[x] for x in t)
        w.append(bytearray(a^b for a,b in zip(w[i-8],t)))
    return [bytes().join(w[i:i+4]) for i in range(0,60,4)]

def _aes_encrypt_block(block, round_keys):
    st=bytearray(block)
    def ark(k):
        for i in range(16): st[i]^=k[i]
    def sub():
        for i in range(16): st[i]=_AES_SBOX[st[i]]
    def shift():
        a=st[:]
        for r in range(4):
            for c in range(4): st[4*c+r]=a[4*((c+r)%4)+r]
    def mix():
        for c in range(4):
            i=4*c; a=st[i:i+4]
            st[i]=_gf_mul(a[0],2)^_gf_mul(a[1],3)^a[2]^a[3]
            st[i+1]=a[0]^_gf_mul(a[1],2)^_gf_mul(a[2],3)^a[3]
            st[i+2]=a[0]^a[1]^_gf_mul(a[2],2)^_gf_mul(a[3],3)
            st[i+3]=_gf_mul(a[0],3)^a[1]^a[2]^_gf_mul(a[3],2)
    ark(round_keys[0])
    for r in range(1,14): sub(); shift(); mix(); ark(round_keys[r])
    sub(); shift(); ark(round_keys[14])
    return bytes(st)

def _aes_ctr(data,key,iv):
    rks=_aes_expand(key); ctr=bytearray(iv); out=bytearray()
    for off in range(0,len(data),16):
        ks=_aes_encrypt_block(bytes(ctr),rks); chunk=data[off:off+16]
        out.extend(a^b for a,b in zip(chunk,ks))
        for i in range(15,-1,-1):
            ctr[i]=(ctr[i]+1)&0xff
            if ctr[i]: break
    return bytes(out)


def classify_secret(secret):
    """Classify an MTProxy secret without raising: 'standard', 'dd' (obfuscated2) or 'ee' (FakeTLS)."""
    try:
        raw = str(secret).strip().lower()
        if raw.startswith('ee'):
            return 'ee'
        if raw.startswith('dd') and len(raw) == 34:
            return 'dd'
        return 'standard'
    except Exception:
        return 'invalid'


def _mt_secret(secret):
    """Return (16-byte secret, mode). Supports plain hex secrets, dd-prefixed
    (obfuscated2 'secure') secrets, and ee-prefixed (FakeTLS) secrets, from which only
    the 16-byte key portion is needed here (the FakeTLS domain suffix, if any, is parsed
    separately by _faketls_secret_parts for the TLS layer)."""
    raw_text=str(secret).strip()
    low=raw_text.lower()
    if low.startswith('ee'):
        raw=bytes.fromhex(low[2:34]) if len(low)>=34 else bytes.fromhex((low[2:]+'0'*32)[:32])
        return raw,'ee'
    if low.startswith('dd') and len(low)==34:
        raw=bytes.fromhex(low[2:]); return raw,'dd'
    try:
        raw=bytes.fromhex(raw_text)
    except ValueError:
        import base64
        try:
            raw=base64.b64decode(raw_text + '='*((4-len(raw_text)%4)%4))
        except Exception:
            raise ValueError('неверный формат secret')
    if len(raw)==17 and raw[0]==0xdd: return raw[1:],'dd'
    if len(raw)<16: raise ValueError('secret короче 16 байт')
    return raw[:16],'standard'

class _AESCTRState:
    """AES-256-CTR keystream state. Uses the vetted 'cryptography' library when it is
    installed (see build_windows.bat), and otherwise falls back to the pure-Python
    implementation above so the scanner keeps working without extra dependencies."""
    def __init__(self,key,iv):
        if _HAS_CRYPTOGRAPHY:
            self._impl='lib'
            self._enc=Cipher(algorithms.AES(key),modes.CTR(iv),backend=default_backend()).encryptor()
        else:
            self._impl='pure'
            self.rks=_aes_expand(key); self.ctr=bytearray(iv)
    def crypt(self,data):
        if self._impl=='lib':
            return self._enc.update(data)
        out=bytearray()
        for off in range(0,len(data),16):
            ks=_aes_encrypt_block(bytes(self.ctr),self.rks); chunk=data[off:off+16]
            out.extend(a^b for a,b in zip(chunk,ks))
            for i in range(15,-1,-1):
                self.ctr[i]=(self.ctr[i]+1)&255
                if self.ctr[i]: break
        return bytes(out)

def _mtproxy_header(secret, mode='standard', dc_id=2):
    # This follows Telegram's MTProxy obfuscated2 construction used by Telegram clients.
    # The first 56 bytes remain random; only bytes 56..63 are encrypted with the
    # continuous AES-CTR stream. See Telegram transport obfuscation / Telethon's
    # MTProxyIO implementation.
    key=secret
    tag=b'\xdd\xdd\xdd\xdd' if mode=='dd' else b'\xee\xee\xee\xee'
    # Reserved first-4-byte patterns a real MTProxy server also refuses, per Telegram's
    # obfuscated2 transport spec (HTTP verbs, a TLS record header, and the dd/ee tags
    # themselves), so our own random header can never collide with them.
    keywords=(b'HEAD',b'POST',b'GET ',b'\x16\x03\x01\x02',b'\xdd\xdd\xdd\xdd',b'\xee\xee\xee\xee')
    while True:
        rnd=bytearray(os.urandom(64))
        if rnd[0]==0xef or bytes(rnd[:4]) in keywords or rnd[4:8]==b'\x00\x00\x00\x00': continue
        break
    rev=bytes(rnd[55:7:-1])
    enc_key=hashlib.sha256(bytes(rnd[8:40])+key).digest(); enc_iv=bytes(rnd[40:56])
    dec_key=hashlib.sha256(rev[:32]+key).digest(); dec_iv=rev[32:48]
    enc=_AESCTRState(enc_key,enc_iv); dec=_AESCTRState(dec_key,dec_iv)
    rnd[56:60]=tag; rnd[60:62]=struct.pack('<h',dc_id)
    encrypted_tail=enc.crypt(bytes(rnd))[56:64]
    header=bytes(rnd[:56])+encrypted_tail
    return header,enc,dec,mode

def _frame_mt(payload, mode):
    if mode=='dd':
        pad=random.randint(0,3); payload=payload+os.urandom(pad)
    return struct.pack('<I',len(payload))+payload

def _read_exact(sock,n):
    buf=bytearray()
    while len(buf)<n:
        chunk=sock.recv(n-len(buf))
        if not chunk: raise ConnectionError('соединение закрыто сервером')
        buf.extend(chunk)
    return bytes(buf)

def _tls_ext(ext_type,data):
    return struct.pack('>HH',ext_type,len(data))+data

def _faketls_secret_parts(secret):
    """Parse an 'ee' FakeTLS secret: ee + 16-byte key (hex) + hex-encoded masquerade
    domain. Falls back to a generic domain if none is present/decodable, which still
    lets the cryptographic handshake proceed (the domain is not part of the digest
    check, only used for the SNI extension's cosmetic realism)."""
    raw=str(secret).strip().lower()
    hexpart=raw[2:] if raw.startswith('ee') else raw
    try:
        b=bytes.fromhex(hexpart)
    except ValueError:
        b=b''
    key16=(b[:16]+b'\x00'*16)[:16]
    domain_bytes=b[16:]
    try:
        domain=domain_bytes.decode('ascii') if domain_bytes else ''
    except Exception:
        domain=''
    if not domain or any(ch not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-' for ch in domain):
        domain='www.google.com'
    return key16,domain

def _build_fake_tls_client_hello(domain,secret16,timestamp=None):
    """Build a FakeTLS ClientHello whose 32-byte 'random' field embeds
    HMAC-SHA256(secret, clienthello-with-zeroed-random)[:28] + (timestamp XOR hmac[28:32]),
    exactly as Telegram's FakeTLS transport requires (see handle_fake_tls_handshake in the
    reference MTProxy server implementation). A real FakeTLS proxy validates this digest
    against its configured secret before accepting the connection, which is what lets us
    verify these proxies automatically instead of leaving them as unverified TCP-only."""
    if timestamp is None: timestamp=int(time.time())
    session_id=os.urandom(32)
    ciphers=[0x1301,0x1302,0x1303,0xc02c,0xc030,0xc02b,0xc02f,0x009e,0x009c,0x0035,0x002f]
    cipher_bytes=b''.join(struct.pack('>H',c) for c in ciphers)
    cipher_suites=struct.pack('>H',len(cipher_bytes))+cipher_bytes
    compression=b'\x01\x00'
    try: sni_name=domain.encode('ascii')
    except Exception: sni_name=b'www.google.com'
    sni_ext=_tls_ext(0x0000,struct.pack('>H',len(sni_name)+3)+b'\x00'+struct.pack('>H',len(sni_name))+sni_name)
    groups_ext=_tls_ext(0x000a,struct.pack('>H',6)+struct.pack('>HHH',0x001d,0x0017,0x0018))
    point_fmt_ext=_tls_ext(0x000b,b'\x01\x00')
    key_share_entry=struct.pack('>H',0x001d)+struct.pack('>H',32)+os.urandom(32)
    key_share_ext=_tls_ext(0x0033,struct.pack('>H',len(key_share_entry))+key_share_entry)
    sig_algs=[0x0403,0x0503,0x0603,0x0807,0x0808,0x0809,0x080a,0x080b,0x0401,0x0501,0x0601,0x0303,0x0301,0x0302]
    sig_bytes=b''.join(struct.pack('>H',x) for x in sig_algs)
    sig_ext=_tls_ext(0x000d,struct.pack('>H',len(sig_bytes))+sig_bytes)
    sup_ver_ext=_tls_ext(0x002b,bytes([4])+struct.pack('>HH',0x0304,0x0303))
    alpn_list=b'\x02h2\x08http/1.1'
    alpn_ext=_tls_ext(0x0010,struct.pack('>H',len(alpn_list))+alpn_list)
    psk_modes_ext=_tls_ext(0x002d,b'\x01\x01')
    exts=sni_ext+groups_ext+point_fmt_ext+key_share_ext+sig_ext+sup_ver_ext+alpn_ext+psk_modes_ext
    body_wo_ext=struct.pack('>H',0x0303)+b'\x00'*32+bytes([len(session_id)])+session_id+cipher_suites+compression
    base_hs_msg_len=4+len(body_wo_ext)+2+len(exts)
    target=600
    pad_content_len=max(0,target-base_hs_msg_len-4)
    if pad_content_len>0 or base_hs_msg_len<512:
        pad_content_len=max(pad_content_len,512-base_hs_msg_len+4,0)
        exts=exts+_tls_ext(0x0015,b'\x00'*pad_content_len)
    ext_block=struct.pack('>H',len(exts))+exts
    hs_body=body_wo_ext+ext_block
    hs_msg=b'\x01'+struct.pack('>I',len(hs_body))[1:]+hs_body
    record=b'\x16\x03\x01'+struct.pack('>H',len(hs_msg))+hs_msg
    DIGEST_POS=11
    zeroed=record[:DIGEST_POS]+b'\x00'*32+record[DIGEST_POS+32:]
    computed=hmac.new(secret16,zeroed,hashlib.sha256).digest()
    ts_bytes=struct.pack('<I',timestamp)
    random_field=computed[:28]+bytes(a^b for a,b in zip(computed[28:32],ts_bytes))
    record=record[:DIGEST_POS]+random_field+record[DIGEST_POS+32:]
    return record

def _read_fake_tls_server_hello(sock,secret16,client_digest,timeout=4.0):
    """Read and cryptographically verify the FakeTLS ServerHello + ChangeCipherSpec +
    fake-certificate records a real FakeTLS proxy sends back. This proves the far end
    actually holds the matching secret, the same kind of proof mtproxy_ping gets from a
    genuine Telegram ResPQ reply for ordinary secrets."""
    sock.settimeout(timeout)
    hdr1=_read_exact(sock,5)
    if hdr1[0:1]!=b'\x16': raise RuntimeError('FakeTLS: сервер не прислал ServerHello')
    len1=struct.unpack('>H',hdr1[3:5])[0]
    body1=_read_exact(sock,len1)
    if body1[0:1]!=b'\x02': raise RuntimeError('FakeTLS: ожидался тип ServerHello')
    rec2=_read_exact(sock,6)
    if rec2[0:1]!=b'\x14': raise RuntimeError('FakeTLS: ожидался ChangeCipherSpec')
    hdr3=_read_exact(sock,5)
    if hdr3[0:1]!=b'\x17': raise RuntimeError('FakeTLS: ожидались фейковые данные сертификата')
    len3=struct.unpack('>H',hdr3[3:5])[0]
    body3=_read_exact(sock,len3)
    combined=hdr1+body1+rec2+hdr3+body3
    DIGEST_POS=11
    srv_digest=combined[DIGEST_POS:DIGEST_POS+32]
    zeroed=combined[:DIGEST_POS]+b'\x00'*32+combined[DIGEST_POS+32:]
    expected=hmac.new(secret16,client_digest+zeroed,hashlib.sha256).digest()
    if not hmac.compare_digest(srv_digest,expected):
        raise RuntimeError('FakeTLS: подпись сервера не совпала с секретом')
    return True

class _FakeTLSSocket:
    """Wraps a connected raw socket so ordinary obfuscated2 MTProto reads/writes are
    transparently framed as TLS 'application data' records, exactly like a real FakeTLS
    tunnel (see FakeTLSStreamReader/Writer in the reference MTProxy server). Everything
    above this class (the obfuscated2 header, req_pq_multi requests, the stability loop)
    is unchanged and works through it without knowing FakeTLS is involved."""
    def __init__(self,sock):
        self.sock=sock; self._buf=bytearray()
    def settimeout(self,t): self.sock.settimeout(t)
    def sendall(self,data):
        MAX=16384+24
        for i in range(0,len(data),MAX):
            chunk=data[i:i+MAX]
            self.sock.sendall(b'\x17\x03\x03'+struct.pack('>H',len(chunk))+chunk)
    def recv(self,n):
        while len(self._buf)<n:
            hdr=_read_exact(self.sock,5)
            if hdr[0:1] not in (b'\x14',b'\x17'):
                raise RuntimeError('FakeTLS: неожиданный тип TLS-записи в потоке')
            ln=struct.unpack('>H',hdr[3:5])[0]
            data=_read_exact(self.sock,ln)
            if hdr[0:1]==b'\x14': continue
            self._buf.extend(data)
        out=bytes(self._buf[:n]); del self._buf[:n]
        return out
    def close(self):
        try:self.sock.close()
        except Exception:pass

def _mtproxy_session_open(p,timeout=3.0):
    host=p['server']; port=int(p['port'])
    kind=classify_secret(p.get('secret',''))
    if kind=='ee':
        key16,domain=_faketls_secret_parts(p.get('secret',''))
        raw=socket.create_connection((host,port),timeout=timeout); raw.settimeout(timeout)
        try:
            client_hello=_build_fake_tls_client_hello(domain,key16,int(time.time()))
            client_digest=client_hello[11:43]
            raw.sendall(client_hello)
            _read_fake_tls_server_hello(raw,key16,client_digest,timeout=timeout)
        except Exception:
            raw.close(); raise
        s=_FakeTLSSocket(raw)
        # Inside a FakeTLS tunnel a real client always uses the "secure"/padded
        # obfuscated2 transport (tag 0xdddddddd) - see PROTO_TAG_SECURE handling in the
        # reference server, which refuses any other tag once is_tls_handshake is true.
        header,enc,dec,mode=_mtproxy_header(key16,'dd',2)
        s.sendall(header)
        return s,enc,dec,mode
    secret,mode=_mt_secret(p.get('secret',''))
    s=socket.create_connection((host,port),timeout=timeout); s.settimeout(timeout)
    header,enc,dec,mode=_mtproxy_header(secret,mode,2)
    s.sendall(header)
    return s,enc,dec,mode

REQ_PQ_MULTI=0xbe7e8ef1
RESPQ_CONSTRUCTOR=struct.pack('<I',0x05162463)
VECTOR_CONSTRUCTOR=struct.pack('<I',0x1cb5c415)

# Telegram's own production RSA public-key fingerprints (8-byte `long`, as sent on the
# wire in ResPQ's server_public_key_fingerprints vector). These are PUBLIC, long-stable
# protocol constants - every legitimate MTProto client (official Telegram apps, Telethon,
# Pyrogram, MadelineProto, the reference MTProxy server itself, ...) embeds exactly these
# same values in order to talk to Telegram at all; this is the open protocol's equivalent
# of a pinned CA certificate, not a secret.
#
# THE BUG THIS FIXES: the previous check only verified that resp_data[:4] looked like the
# ResPQ constructor and that the server echoed our own nonce back - both are trivial for
# ANY server to fake without ever being connected to Telegram (it only has to mirror bytes
# the client itself sent). A "fake"/dead proxy that implements just enough of the wire
# format to produce a plausible-looking ResPQ would sail through that check every time,
# which is almost certainly why proxies the scanner marked "Онлайн - Проверен" turned out
# not to work in real Telegram. Checking that the response's fingerprint vector contains
# one of Telegram's REAL public keys below closes that gap: a server that cannot present
# one of these exact values is not actually relaying to Telegram's network (producing them
# without real access to Telegram would require already knowing Telegram's own published
# keys for no reason, which fake/non-functional proxy lists have no cause to bother with).
#
# Source: these exact values (and the comments confirming them) come straight from
# Pyrogram's own rsa.py (github.com/pyrogram/pyrogram, MTProto client library), computed
# here as the raw unsigned-64-bit wire value so comparison against parsed bytes is
# unambiguous regardless of signed/unsigned interpretation.
TELEGRAM_RSA_FINGERPRINTS=frozenset((
    0xc3b42b026ce86b21,  # Telegram servers #1
    0x0bc35f3509f7b7a5,  # Telegram servers #2
    0x15ae5fa8b5529542,  # Telegram servers #3
    0xaeae98e13cd7f94f,  # Telegram servers #4
    0x5a181b2235057d98,  # Telegram servers #5
    0x995effd323b5db80,  # CDN DC-121
    0x254672538e935938,  # CDN DC-140
    0xc884b3e62d09e5c5,  # CDN DC-201
    0xbb27580fd5b01626,  # CDN DC-203
))

def _tl_parse_bytes_field(data,offset):
    """Parse one TL bare 'bytes'/'string' field (used for ResPQ's `pq`) at `offset`.
    Returns (value, next_offset). Handles both the short form (1-byte length < 254) and
    the long form (0xFE marker + 3-byte little-endian length), including the padding to a
    4-byte boundary that TL requires in both cases."""
    first=data[offset]
    if first<254:
        length=first; start=offset+1
    else:
        length=int.from_bytes(data[offset+1:offset+4],'little'); start=offset+4
    end=start+length
    pad=(-(end-offset))%4
    return data[start:end], end+pad

def _verify_telegram_fingerprint(resp_data):
    """Parse ResPQ's server_nonce/pq/server_public_key_fingerprints fields (everything
    after the nonce we already checked) and confirm the vector contains at least one of
    Telegram's real published RSA key fingerprints (TELEGRAM_RSA_FINGERPRINTS above).
    Raises RuntimeError if the response is malformed or presents no genuine fingerprint -
    both are treated as "this is not a real Telegram/MTProxy response"."""
    try:
        off=36  # 4 (constructor, already checked) + 16 (nonce, already checked) + 16 (server_nonce)
        pq,off=_tl_parse_bytes_field(resp_data,off)
        if not (1<=len(pq)<=16): raise ValueError(f'неожиданная длина pq: {len(pq)}')
        if resp_data[off:off+4]!=VECTOR_CONSTRUCTOR: raise ValueError('нет Vector<long> с fingerprints')
        count=struct.unpack('<I',resp_data[off+4:off+8])[0]
        if not (1<=count<=16): raise ValueError(f'неожиданное число fingerprints: {count}')
        fp_off=off+8
        fingerprints=[struct.unpack('<Q',resp_data[fp_off+i*8:fp_off+i*8+8])[0] for i in range(count)]
    except Exception as e:
        raise RuntimeError(f'ResPQ повреждён или не похож на настоящий Telegram-ответ: {e}')
    if not any(fp in TELEGRAM_RSA_FINGERPRINTS for fp in fingerprints):
        raise RuntimeError('сервер не предъявил подлинный RSA-ключ Telegram (похоже на фейковый/нерабочий прокси)')

def _next_msg_id(mid_state):
    """MTProto message ids must strictly increase within a connection and, for
    client->server content-related messages, have their low 2 bits cleared."""
    msg_id=int(time.time()*(2**32)) & ~3
    if msg_id<=mid_state['last']: msg_id=mid_state['last']+4
    mid_state['last']=msg_id
    return msg_id

def _build_unencrypted_message(data,msg_id):
    # MTProto "unencrypted message" envelope: auth_key_id(0) + message_id + message_length + data.
    # The previous implementation sent only `data` (the bare constructor+nonce) with no
    # envelope at all, so every real MTProxy/Telegram server rejected or ignored it and the
    # "stability" / Telegram-verified check never actually succeeded (see debug log: every
    # STABILITY run shows checks=0).
    return b'\x00'*8+struct.pack('<Q',msg_id)+struct.pack('<I',len(data))+data

def _mtproxy_request(s,enc,dec,mode,mid_state,timeout=2.5):
    nonce=os.urandom(16)
    data=struct.pack('<I',REQ_PQ_MULTI)+nonce
    msg_id=_next_msg_id(mid_state)
    message=_build_unencrypted_message(data,msg_id)
    frame=_frame_mt(message,mode)
    started=time.perf_counter(); s.settimeout(timeout); s.sendall(enc.crypt(frame))
    hdr=dec.crypt(_read_exact(s,4)); length=struct.unpack('<I',hdr)[0]
    if length<20 or length>1024*1024: raise RuntimeError(f'неверная длина MTProto-ответа: {length}')
    body=dec.crypt(_read_exact(s,length))
    elapsed=(time.perf_counter()-started)*1000.0
    if len(body)<20: raise RuntimeError('MTProto-ответ короче заголовка сообщения')
    resp_data=body[20:]
    if resp_data[:4]!=RESPQ_CONSTRUCTOR: raise RuntimeError('Telegram не вернул ResPQ')
    if resp_data[4:20]!=nonce: raise RuntimeError('ResPQ nonce не совпал')
    if len(resp_data)<36: raise RuntimeError('ResPQ короче ожидаемого (нет server_nonce)')
    _verify_telegram_fingerprint(resp_data)  # см. комментарий у TELEGRAM_RSA_FINGERPRINTS: отсекает фейковые прокси
    return elapsed

def mtproxy_ping(p, timeout=3.0):
    """Open a fresh connection and perform one real Telegram MTProto req_pq_multi
    round-trip. This is the automatic, no-user-interaction check that a proxy is a
    genuine working MTProxy (not just an open TCP port)."""
    s=enc=dec=None
    try:
        s,enc,dec,mode=_mtproxy_session_open(p,timeout)
        mid_state={'last':0}
        return _mtproxy_request(s,enc,dec,mode,mid_state,timeout=min(timeout,2.5))
    finally:
        if s:
            try:s.close()
            except Exception:pass


def tcp_probe(p,timeout=2.5):
    started=time.perf_counter(); ip=resolve_ip(p['server'])
    if not ip:return False,None,None,'DNS failed'
    try:
        with socket.create_connection((ip,p['port']),timeout=timeout):
            return True,round((time.perf_counter()-started)*1000,1),ip,None
    except Exception as e:return False,None,ip,str(e)


STABILITY_TICK=0.5  # fixed per spec: check ping every 0.5s while routing real traffic through the proxy
# ИСПРАВЛЕНО (v28, пункт №3 обращения — "дозапросы вообще бесполезны, даже 5 раундов
# ничего не находят"): раньше каждый тик стабильности обязан был уложиться в
# ЖЁСТКО ЗАШИТЫЕ 100мс, НИКАК не связанные с полем "Макс. ping" в настройках — даже
# если пользователь явно указал, что согласен на ping до 1000мс. Анализ debug-лога
# пользователя показал, что это и есть настоящая причина проблемы: почти ВСЕ (1094 из
# 1137, ~96%) отброшенных на стабильности прокси отбраковывались именно по "ping > 100
# мс", хотя их реальный ping (127-145мс) укладывался в указанный пользователем лимит
# 1000мс с большим запасом — то есть дозапрос действительно находил новые рабочие
# источники и новые кандидаты (это видно по логу: "new_sources=15 new_candidates=160"),
# но скрытый отдельный порог стабильности отбрасывал практически всё до того, как
# прокси попадал в список найденных. Теперь порог стабильности берётся из того же
# самого "Макс. ping", который пользователь уже настраивает — отдельного скрытого
# значения больше нет.
STABILITY_MAX_PING_DEFAULT=100.0  # запасное значение, если вызывающий код не передал max_ping явно

# Проверка "других видов прокси" (пункт №1 обращения) — так же, как MTProto-проверка
# выше делает настоящий протокольный запрос, а не просто проверяет открытый порт, эти
# две функции делают настоящее подтверждение протокола: реальное SOCKS5-рукопожатие
# (и CONNECT до домена Telegram — не просто до "чего угодно", раз это сканер именно
# telegram-прокси) и настоящий HTTP CONNECT-туннель. Общая цель прокси здесь одна и та
# же — довести трафик до Telegram, поэтому и "боевая" проверка обеих нацелена именно
# туда (core.telegram.org:443), а не на произвольный тестовый адрес.
_PROXY_CHECK_TARGET_HOST='core.telegram.org'
_PROXY_CHECK_TARGET_PORT=443

def _check_socks5(p,timeout):
    """Настоящее SOCKS5-рукопожатие (RFC 1928/1929) + CONNECT до Telegram — открытый
    порт, который не говорит по SOCKS5, или говорит, но не может докуда-либо
    достучаться, отбраковывается, а не засчитывается как рабочий прокси."""
    ip=resolve_ip(p['server'])
    if not ip: return False,None,None,'DNS failed','socks5'
    user=p.get('user') or None; pwd=p.get('password') or ''
    started=time.perf_counter()
    try:
        with socket.create_connection((ip,p['port']),timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b'\x05'+(b'\x02\x00\x02' if user else b'\x01\x00'))
            resp=_read_exact(s,2)
            if resp[0]!=5: return False,None,ip,'не SOCKS5 (неверная версия в ответе)','socks5'
            method=resp[1]
            if method==0xFF: return False,None,ip,'сервер не принял ни одного метода авторизации','socks5'
            if method==2:
                if not user: return False,None,ip,'сервер требует логин/пароль, которых нет','socks5'
                ub=user.encode('utf-8')[:255]; pb=pwd.encode('utf-8')[:255]
                s.sendall(b'\x01'+bytes([len(ub)])+ub+bytes([len(pb)])+pb)
                r=_read_exact(s,2)
                if r[1]!=0: return False,None,ip,'неверный логин/пароль SOCKS5','socks5'
            host_b=_PROXY_CHECK_TARGET_HOST.encode('ascii')
            req=b'\x05\x01\x00\x03'+bytes([len(host_b)])+host_b+struct.pack('>H',_PROXY_CHECK_TARGET_PORT)
            s.sendall(req)
            rep=_read_exact(s,4)
            if rep[1]!=0: return False,None,ip,f'SOCKS5 CONNECT отклонён (код {rep[1]})','socks5'
            atyp=rep[3]
            if atyp==1: _read_exact(s,4+2)
            elif atyp==3: n=_read_exact(s,1)[0]; _read_exact(s,n+2)
            elif atyp==4: _read_exact(s,16+2)
            ms=round((time.perf_counter()-started)*1000,1)
            return True,ms,ip,None,'socks5'
    except Exception as e:
        return False,None,ip,str(e),'socks5'


def _check_http_proxy(p,timeout):
    """Настоящий HTTP CONNECT-туннель до Telegram через прокси (RFC 7231) — тот же
    принцип: подтверждаем, что прокси реально может протащить TLS-трафик до
    core.telegram.org, а не просто держит порт открытым."""
    ip=resolve_ip(p['server'])
    if not ip: return False,None,None,'DNS failed','http'
    started=time.perf_counter()
    try:
        with socket.create_connection((ip,p['port']),timeout=timeout) as s:
            s.settimeout(timeout)
            target=f'{_PROXY_CHECK_TARGET_HOST}:{_PROXY_CHECK_TARGET_PORT}'
            lines=[f'CONNECT {target} HTTP/1.1',f'Host: {target}','Proxy-Connection: Keep-Alive']
            if p.get('user'):
                b64=base64.b64encode(f"{p['user']}:{p.get('password','')}".encode('utf-8')).decode('ascii')
                lines.append(f'Proxy-Authorization: Basic {b64}')
            s.sendall(('\r\n'.join(lines)+'\r\n\r\n').encode('ascii','ignore'))
            resp=b''
            while b'\r\n\r\n' not in resp and len(resp)<8192:
                chunk=s.recv(4096)
                if not chunk: break
                resp+=chunk
            line=resp.split(b'\r\n',1)[0].decode('latin-1','replace')
            ms=round((time.perf_counter()-started)*1000,1)
            if re.match(r'^HTTP/1\.[01]\s+200\b',line):
                return True,ms,ip,None,'http'
            return False,None,ip,f'HTTP CONNECT отклонён: {line[:100] or "пустой ответ"}','http'
    except Exception as e:
        return False,None,ip,str(e),'http'


def _check_web_proxy(p,timeout,ssl_context=None,port=443):
    """ЧЕСТНАЯ (настоящая, но не полная) проверка WEB-прокси.

    Пользователь прислал реальную ссылку подключения WEB-прокси в Telegram Desktop
    ("tg://webproxy?server=...&secret=...") — выяснилось, что это действительно
    существующий, рабочий тип прокси (см. официальный репозиторий
    telegramdesktop/tproxy-server), а не выдумка списков прокси, как считалось раньше.
    По устройству: это обычный HTTPS-сайт на 443 порту (своём домене провайдера
    прокси), который после правильного секрета открывает скрытый "мост"
    (WebSocket/long-poll), прозрачно прокидывающий трафик до настоящего MTProxy-сервера.

    НО: сам алгоритм моста (как именно из server+secret получить токен для запроса
    моста) описан в закрытом PROTOCOL.md, которого Telegram публично не выкладывал —
    поэтому пройти его по-настоящему (как мы делаем для MTProto/SOCKS5/HTTP выше) здесь
    нельзя: это были бы догадки, а не проверка. Честно проверяем то, что ДЕЙСТВИТЕЛЬНО
    задокументировано и наблюдаемо: что по адресу из ссылки есть настоящий работающий
    HTTPS-сервер — то есть делаем реальное TLS-рукопожатие (с SNI и проверкой
    сертификата, а не просто открываем TCP-порт) и реальный HTTP-запрос к нему. Это
    заметно строже старого "порт отвечает" (tcp-only), но честно помечается отдельным
    методом 'web' — не выдаётся за полную проверку протокола моста до Telegram.

    `ssl_context`/`port` — только для юнит-тестов (локальный HTTPS-сервер с тестовым
    сертификатом на нестандартном порту); в реальной работе всегда используются
    значения по умолчанию (настоящая системная проверка сертификата, порт 443 — так
    устроен сам тип WEB-прокси)."""
    ip=resolve_ip(p['server'])
    if not ip: return False,None,None,'DNS failed','web'
    started=time.perf_counter()
    raw=None
    try:
        raw=socket.create_connection((ip,port),timeout=timeout)
        ctx=ssl_context or ssl.create_default_context()
        with ctx.wrap_socket(raw,server_hostname=p['server']) as tls:
            tls.settimeout(timeout)
            req=f"GET / HTTP/1.1\r\nHost: {p['server']}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            tls.sendall(req.encode('ascii','ignore'))
            resp=b''
            while b'\r\n' not in resp and len(resp)<4096:
                chunk=tls.recv(2048)
                if not chunk: break
                resp+=chunk
            line=resp.split(b'\r\n',1)[0].decode('latin-1','replace')
            ms=round((time.perf_counter()-started)*1000,1)
            if re.match(r'^HTTP/1\.[01]\s+\d{3}\b',line):
                return True,ms,ip,None,'web'
            return False,None,ip,f'неожиданный ответ сервера: {line[:100] or "пусто"}','web'
    except ssl.SSLCertVerificationError as e:
        return False,None,ip,f'TLS-сертификат не прошёл проверку: {e}','web'
    except Exception as e:
        return False,None,ip,str(e),'web'
    finally:
        if raw:
            try: raw.close()
            except Exception: pass


def check_proxy_online(p,timeout=2.6):
    """Automatic, no-user-interaction verification that a candidate is a real, working
    proxy. Dispatches on p['ptype']:
      'mtproto' (default) — plain TCP connect, then a genuine protocol round-trip
        through the proxy so an open port that isn't actually speaking MTProto/FakeTLS
        gets rejected. Ordinary/obfuscated ('standard'/'dd') secrets get a real MTProto
        req_pq_multi exchange; FakeTLS ('ee') secrets get the FakeTLS handshake (which
        cryptographically proves the proxy holds the matching secret) followed by the
        same req_pq_multi exchange inside the tunnel. Both paths give equally real
        verification; only their label differs, so the UI can note FakeTLS proxies
        distinctly.
      'socks5'/'http' — real protocol handshake + a CONNECT through to Telegram (see
        _check_socks5/_check_http_proxy) — пункт №1 обращения ("другие виды прокси").
      'web' — настоящее TLS-рукопожатие (с проверкой сертификата) + HTTP-запрос к
        HTTPS-серверу прокси (см. _check_web_proxy) — заметно строже, чем просто
        "порт отвечает", но без полной проверки протокола моста до Telegram (его
        алгоритм Telegram публично не документирует — см. комментарий у
        _check_web_proxy про PROTOCOL.md).

    Holds NET_GATE for its whole run (see comment above NET_GATE) so this quick check
    and the much longer стability check below always share one combined concurrency
    budget sized to «Параллельность проверок», instead of each keeping its own
    independent pool and silently multiplying the real number of open sockets."""
    with NET_GATE:
        ptype=p.get('ptype','mtproto')
        if ptype=='socks5':
            return _check_socks5(p,timeout)
        if ptype=='http':
            return _check_http_proxy(p,timeout)
        if ptype=='web':
            return _check_web_proxy(p,timeout)
        ok,tcp_ms,ip,err=tcp_probe(p,timeout=min(2.2,timeout))
        if not ok:
            return False,None,ip,err,'tcp'
        kind=classify_secret(p.get('secret',''))
        if kind in ('standard','dd','ee'):
            try:
                ms=mtproxy_ping(p,timeout=max(1.5,timeout if kind!='ee' else timeout+1.0))
                return True,ms,ip,None,('mtproto-tls' if kind=='ee' else 'mtproto')
            except Exception as e:
                label='FakeTLS-проверка' if kind=='ee' else 'MTProto-проверка'
                return False,None,ip,f'{label} не пройдена: {e}',('mtproto-tls' if kind=='ee' else 'mtproto')
        return True,tcp_ms,ip,None,'tcp-only'


# Пункт №2 следующего обращения пользователя: "Улучшить проверку стабильности, сейчас
# она нормально работает только с MTProto Proxy" — подтвердилось: раньше stability_job()
# вообще не запускал проверку стабильности для SOCKS5/HTTP/WEB (см. условие
# `method in (...)` в scan()), они просто принимались сразу после одной-единственной
# быстрой проверки. Теперь стабильность считается для всех типов, которые это
# поддерживают — см. STABILITY_SUPPORTED_METHODS и диспетчер stability_test() ниже.
STABILITY_SUPPORTED_METHODS={'mtproto','mtproto-tls','socks5','http','web'}

def stability_test(p,seconds,stop_event,abort_event,max_ping=STABILITY_MAX_PING_DEFAULT):
    """Диспетчер: выбирает реализацию проверки стабильности по типу прокси. MTProto
    использует специализированную версию с одним персистентным соединением
    (_stability_test_mtproto); SOCKS5/HTTP/WEB — общую версию с повторной полной
    проверкой на каждом тике (_stability_test_generic, см. его docstring про то, почему
    выбран именно такой подход, а не один держащийся открытым сырой сокет).

    `max_ping` — потолок задержки одного тика (в мс), выше которого прокси отбрасывается;
    scan() передаёт сюда то же самое значение, что пользователь указал в «Макс. ping» (см.
    комментарий у STABILITY_MAX_PING_DEFAULT про то, почему раньше здесь был отдельный
    зашитый порог 100мс, не связанный с этой настройкой)."""
    ptype=p.get('ptype','mtproto')
    if ptype=='socks5':
        return _stability_test_generic(p,seconds,stop_event,abort_event,lambda:_check_socks5(p,2.6),max_ping)
    if ptype=='http':
        return _stability_test_generic(p,seconds,stop_event,abort_event,lambda:_check_http_proxy(p,2.6),max_ping)
    if ptype=='web':
        return _stability_test_generic(p,seconds,stop_event,abort_event,lambda:_check_web_proxy(p,2.6),max_ping)
    return _stability_test_mtproto(p,seconds,stop_event,abort_event,max_ping)


def _stability_test_generic(p,seconds,stop_event,abort_event,check_once,max_ping=STABILITY_MAX_PING_DEFAULT):
    """Стабильность для SOCKS5/HTTP/WEB.

    У MTProto стабильность держит ОДНО соединение открытым и гоняет через него
    настоящий трафик каждые STABILITY_TICK секунд (см. _stability_test_mtproto ниже) —
    это естественно для MTProto: там один персистентный TCP-сокет с чёткими границами
    одного запроса/ответа, не зависящими от HTTP/TLS-обвязки. Для SOCKS5/HTTP/WEB
    выбран другой, но не менее честный подход: каждый тик — это ПОЛНОСТЬЮ новая
    настоящая проверка (новое соединение + полное рукопожатие протокола + прогон через
    core.telegram.org/HTTPS — та же функция, что и при самом первом обнаружении прокси,
    см. check_once). Это даже строже в одном смысле: ловит не только "обрывается ли уже
    открытое соединение", но и "умеет ли прокси стабильно принимать НОВЫЕ соединения" —
    а держать один сырой сокет открытым несколько секунд БЕЗ протокола поверх (чтобы, как
    у MTProto, чисто измерять round-trip одного тика через HTTP keep-alive) для
    SOCKS5/HTTP/WEB устроено сложнее и легче сломать, чем повторить уже проверенную
    полную проверку. Критерий приёма — тот же, что и у MTProto: каждый тик обязан
    пройти и уложиться в `max_ping` мс (настройка «Макс. ping»), иначе прокси сразу
    отбрасывается, не дожидаясь конца срока."""
    NET_GATE.acquire()
    started=time.perf_counter(); checks=0; worst=0.0
    log(f'STABILITY START {p["server"]}:{p["port"]} seconds={seconds} ptype={p.get("ptype")} max_ping={max_ping}')
    try:
        deadline=started+seconds; next_tick=started
        while True:
            if time.perf_counter()>=deadline: break
            if stop_event.is_set() or abort_event.is_set():
                return False,'сканирование остановлено'
            ok,ms,_ip,err,_method=check_once()
            if not ok:
                log(f'STABILITY REJECT {p["server"]}:{p["port"]}: {err}')
                return False,err or 'проверка не прошла'
            checks+=1; worst=max(worst,ms); p['ping']=round(ms,1)
            if ms>max_ping:
                log(f'STABILITY REJECT {p["server"]}:{p["port"]} ping={ms:.1f}ms > max_ping={max_ping}ms')
                return False,f'ping {ms:.1f} ms > {max_ping:.0f} ms'
            next_tick+=STABILITY_TICK
            remaining=next_tick-time.perf_counter()
            if remaining>0: time.sleep(min(remaining,max(0,deadline-time.perf_counter())))
        elapsed=time.perf_counter()-started
        passed=elapsed>=seconds*0.9 and checks>=max(1,int(seconds/STABILITY_TICK)-1)
        log(f'STABILITY {"PASS" if passed else "FAIL"} {p["server"]}:{p["port"]} checks={checks} worst={worst:.1f} elapsed={elapsed:.2f}')
        return passed,(None if passed else 'недостаточно успешных проверок')
    except Exception as e:
        log(f'STABILITY ERROR {p["server"]}:{p["port"]}: {e}',True)
        return False,str(e)
    finally:
        NET_GATE.release()


def _stability_test_mtproto(p,seconds,stop_event,abort_event,max_ping=STABILITY_MAX_PING_DEFAULT):
    """Run the whole stability check on ONE persistent MTProxy connection, sending real
    Telegram MTProto traffic (req_pq_multi) every STABILITY_TICK seconds for the full
    requested duration. Returns (passed, detail). The caller only adds the proxy to the
    user-visible list if this returns True, so a proxy is fully verified BEFORE it is
    handed to the user, and any tick above `max_ping` ms (the user's own "Макс. ping"
    setting — see STABILITY_MAX_PING_DEFAULT) aborts and drops it immediately rather
    than waiting out the rest of the duration.

    Acquires NET_GATE for the ENTIRE duration (connect + every tick), not just for
    individual reads/writes — a stability check holds one real connection open for
    several seconds, so it must occupy one full slot of the shared concurrency budget,
    the same way check_proxy_online does. This is the main fix for the connection-reset/
    timeout storm seen in the debug log on weak connections: before, this pool (up to
    concurrency//4 extra threads) ran fully on top of the main check pool with no shared
    limit at all."""
    NET_GATE.acquire()
    started=time.perf_counter(); checks=0; worst=0.0
    s=enc=dec=None
    log(f'STABILITY START {p["server"]}:{p["port"]} seconds={seconds} max_ping={max_ping}')
    try:
        s,enc,dec,mode=_mtproxy_session_open(p,timeout=4.0)
        mid_state={'last':0}
        deadline=started+seconds; next_tick=started
        while True:
            if time.perf_counter()>=deadline: break
            if stop_event.is_set() or abort_event.is_set():
                return False,'сканирование остановлено'
            try:
                ms=_mtproxy_request(s,enc,dec,mode,mid_state,timeout=max(1.2,min(4.0,1.2+seconds)))
            except Exception as e:
                log(f'STABILITY REJECT {p["server"]}:{p["port"]}: {e}')
                return False,str(e)
            checks+=1; worst=max(worst,ms); p['ping']=round(ms,1)
            if ms>max_ping:
                log(f'STABILITY REJECT {p["server"]}:{p["port"]} ping={ms:.1f}ms > max_ping={max_ping}ms')
                return False,f'ping {ms:.1f} ms > {max_ping:.0f} ms'
            next_tick+=STABILITY_TICK
            remaining=next_tick-time.perf_counter()
            if remaining>0: time.sleep(min(remaining,max(0,deadline-time.perf_counter())))
        elapsed=time.perf_counter()-started
        passed=elapsed>=seconds*0.9 and checks>=max(1,int(seconds/STABILITY_TICK)-1)
        log(f'STABILITY {"PASS" if passed else "FAIL"} {p["server"]}:{p["port"]} checks={checks} worst={worst:.1f} elapsed={elapsed:.2f}')
        return passed,(None if passed else 'недостаточно успешных проверок')
    except Exception as e:
        log(f'STABILITY ERROR {p["server"]}:{p["port"]}: {e}',True)
        return False,str(e)
    finally:
        if s:
            try:s.close()
            except Exception:pass
        NET_GATE.release()


class _RateLimiter:
    """Sliding-window limiter so we never fire more than max_calls per period.
    ip-api.com's free tier allows ~45 req/min; hammering it faster than that was
    causing the connection resets seen throughout the debug log (GEO FAIL ...
    ConnectionResetError), because the old code called geo() one-by-one inline in the
    main scan loop for every online proxy with no throttling at all."""
    def __init__(self,max_calls,period):
        self.max_calls=max_calls; self.period=period; self.calls=collections.deque(); self.lock=threading.Lock()
    def acquire(self):
        while True:
            with self.lock:
                now=time.time()
                while self.calls and now-self.calls[0]>self.period: self.calls.popleft()
                if len(self.calls)<self.max_calls:
                    self.calls.append(now); return
                wait=self.period-(now-self.calls[0])
            time.sleep(max(0.05,wait))

# Общий "шлюз" сетевой параллельности. ДО этого исправления TCP/MTProto-проверки
# (пул из «Параллельность проверок» потоков), проверка стабильности (ОТДЕЛЬНЫЙ пул
# ещё на concurrency//4 потоков, работающий ОДНОВРЕМЕННО с первым) и geo()-запросы
# сами по себе могли суммарно открывать заметно больше одновременных соединений, чем
# пользователь указал в «Параллельность проверок» — именно это и объясняет массовые
# ConnectionResetError/TimeoutError в присланном логе (550+ таймаутов стабильности и
# десятки сброшенных geo-запросов подряд) при слабом/нестабильном интернете. Теперь
# ВСЕ сетевые операции проверки (TCP/MTProto-проверка, стабильность, geo) обязаны
# получить разрешение у этого общего семафора перед тем как открыть соединение — он
# пересоздаётся в scan() с размером ровно в «Параллельность проверок», так что реальное
# число одновременных соединений никогда не превышает то, что выбрал пользователь,
# независимо от того, сколько отдельных пулов потоков его просит.
NET_GATE=threading.Semaphore(64)

_GEO_LIMITER=_RateLimiter(40,60)
_GEO_CACHE={}
_GEO_CACHE_LOCK=threading.Lock()

def geo(ip):
    if not ip:return {}
    with _GEO_CACHE_LOCK:
        if ip in _GEO_CACHE: return _GEO_CACHE[ip]
    _GEO_LIMITER.acquire()
    result={}
    try:
        # Геоданные — это необязательная косметика (страна/провайдер в списке), а НЕ
        # проверка самого прокси, поэтому здесь используется быстрый однопроходный
        # fast_probe_get() без тяжёлой цепочки повторов+curl+powershell из http_get():
        # раньше один неудачный geo-запрос мог занимать до ~20-25 секунд (2 попытки
        # urllib + curl + powershell), удерживая слот NET_GATE и без всякой пользы
        # замедляя остальные проверки — теперь это максимум несколько секунд.
        with NET_GATE:
            data=fast_probe_get(IPINFO.format(ip=urllib.parse.quote(ip)),4.0)
        if data:
            o=json.loads(data)
            if o.get('status')=='success': result=o
    except Exception as e:
        log(f'GEO FAIL ip={ip}: {type(e).__name__}: {e}')
    with _GEO_CACHE_LOCK:
        _GEO_CACHE[ip]=result
    return result


def provider_name(p):
    g=p.get('geo') or {}; return ' '.join(str(g.get(k,'')) for k in ('isp','org','as')).strip()


def country_name(p):
    g=p.get('geo') or {}; return COUNTRY_NAMES.get(g.get('countryCode',''),g.get('country','Неизвестно'))


def tg_installed():
    if sys.platform!='win32': return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT,r'tg\shell\open\command') as k:
            v,_=winreg.QueryValueEx(k,None); return bool(v)
    except Exception:return False


def add_to_telegram(link):
    if sys.platform=='win32':
        # Prefer Windows Shell protocol activation, exactly like TG WS Proxy's "Open in Telegram".
        try:
            os.startfile(link); return True
        except Exception: pass
        try:
            subprocess.Popen(['cmd','/c','start','','%s'%link],creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)); return True
        except Exception: pass
    return False


class ToolTip:
    """Small hover tooltip attached to a widget (used for the '?' help badges next to
    each setting, so people can learn what a control does without leaving the app)."""
    def __init__(self, widget, text, wraplength=300):
        self.widget=widget; self.text=text; self.wraplength=wraplength; self.tip=None
        widget.bind('<Enter>', self.show); widget.bind('<Leave>', self.hide); widget.bind('<ButtonPress>', self.hide)
    def show(self, _event=None):
        if self.tip or not self.text: return
        try:
            x=self.widget.winfo_rootx()+10; y=self.widget.winfo_rooty()+self.widget.winfo_height()+10
        except Exception:
            return
        self.tip=tk.Toplevel(self.widget); self.tip.wm_overrideredirect(True)
        try: self.tip.wm_geometry(f'+{x}+{y}')
        except Exception: pass
        try: self.tip.attributes('-topmost', True)
        except Exception: pass
        tk.Label(self.tip, text=self.text, justify='left', background=COLORS['panel2'], foreground=COLORS['text'],
                 relief='solid', borderwidth=1, wraplength=self.wraplength, font=('Segoe UI',11), padx=10, pady=7).pack()
    def hide(self, _event=None):
        if self.tip:
            try: self.tip.destroy()
            except Exception: pass
            self.tip=None


class App:
    def __init__(self,root):
        self.root=root; root.title(APP_TITLE); root.geometry('1360x900')
        # Минимальный размер окна задан один раз и не меняется в рантайме (окно никогда
        # само не раздвигается/не "спорит" с пользователем при перетаскивании рамки) —
        # если контенту не хватает места, верхний блок с настройками становится
        # прокручиваемым (см. _relayout), а не раздувает окно.
        root.minsize(MIN_WINDOW_WIDTH,MIN_WINDOW_HEIGHT)
        root.configure(bg=COLORS['bg'])
        self._layout_narrow=None; self._resize_job=None
        self.q=queue.Queue(); self.stop_event=threading.Event(); self.scan_running=False; self.all_results=[]
        self.settings={'country':'Все страны','provider':'Все провайдеры','max_ping':1000,'limit':10,'interval':1.0,
                       'auto_ping':True,'only_ok':False,'stability':False,'stability_seconds':3.0,
                       'dynamic_target':40,'concurrency':64,'dynamic_sources':False,'enhanced_search':False,
                       'discovery_time':25,'topup_rounds':MAX_TOPUP_ROUNDS,'github_token':'','telegram_proxy':'','tg_gateways':True,'ptype_mtproto':True,'ptype_socks5':False,'ptype_http':False,'ptype_web':False}
        self._filter_state={}
        log(f'APP START version=v30 crypto_backend={"cryptography" if _HAS_CRYPTOGRAPHY else "pure-python"} icons_backend={"pillow" if _HAS_PIL else "none(fallback text)"} python={sys.version.split()[0]} platform={platform.platform()} executable={sys.executable} log={LOG_FILE}')
        self._build_styles(); self._build_ui()
        self.load_settings(silent=True)  # restore whatever the person saved last time, quietly
        root.after(80,self.poll); threading.Thread(target=self.ping_loop,daemon=True).start()

    def _build_styles(self):
        s=ttk.Style();
        try:s.theme_use('clam')
        except:pass
        # Шрифт: если рядом с программой есть файлы Inter и их удалось подключить
        # (см. _load_bundled_fonts выше) — используем более современный Inter,
        # иначе — красивый и всегда доступный на Windows шрифт по умолчанию, Segoe UI.
        import tkinter.font as _tkfont
        try: _families=set(_tkfont.families())
        except Exception: _families=set()
        if _INTER_AVAILABLE and 'Inter UI' in _families:
            FONT='Inter UI'; FONTB='Inter UI SemiBold' if 'Inter UI SemiBold' in _families else 'Inter UI'
        else:
            FONT='Segoe UI'; FONTB='Segoe UI Semibold'
        log(f'FONT selected: {FONT} / {FONTB} (bundled Inter loaded={_INTER_AVAILABLE})')
        # Базовые размеры шрифта подняты ещё на 1pt по всей программе (в дополнение к
        # предыдущему round'у) — просили увеличить, потому что местами текст всё ещё
        # казался мелковатым. Все размеры ниже — целые числа: в этой сборке Tk дробный
        # размер (напр. 9.5) делает текст чекбоксов полностью невидимым (найдено и исправлено
        # в одном из прошлых прогонов), поэтому дробных размеров здесь намеренно нет нигде.
        s.configure('.',font=(FONT,12)); s.configure('TFrame',background=COLORS['bg'])
        s.configure('Title.TLabel',background=COLORS['bg'],foreground=COLORS['text'],font=(FONTB,21))
        s.configure('Subtitle.TLabel',background=COLORS['bg'],foreground=COLORS['muted'],font=(FONT,12))
        s.configure('Sub.TLabel',background=COLORS['bg'],foreground=COLORS['muted'],font=(FONT,11))
        s.configure('Panel.TFrame',background=COLORS['panel']); s.configure('Panel2.TFrame',background=COLORS['panel2'])
        s.configure('Panel.TLabel',background=COLORS['panel'],foreground=COLORS['text'])
        s.configure('Panel2.TLabel',background=COLORS['panel2'],foreground=COLORS['text'])
        s.configure('Muted.TLabel',background=COLORS['panel'],foreground=COLORS['muted'],font=(FONT,11))
        s.configure('MutedAlt.TLabel',background=COLORS['panel2'],foreground=COLORS['muted'],font=(FONT,11))
        s.configure('CardIcon.TLabel',background=COLORS['panel'],foreground=COLORS['accent'],font=(FONT,17))
        s.configure('CardTitle.TLabel',background=COLORS['panel'],foreground=COLORS['text'],font=(FONTB,14))
        s.configure('Section.TLabel',background=COLORS['panel'],foreground=COLORS['text'],font=(FONTB,13))
        for key,color in (('',COLORS['text']),('Blue',COLORS['blue']),('Green',COLORS['green']),('Accent2',COLORS['accent2']),('Yellow',COLORS['yellow'])):
            s.configure(f'Value{key}.TLabel',background=COLORS['panel2'],foreground=color,font=(FONTB,21))
        s.configure('Caption.TLabel',background=COLORS['panel'],foreground=COLORS['accent'],font=(FONTB,11))
        s.configure('StatusPill.TLabel',background=COLORS['panel3'],foreground=COLORS['muted'],font=(FONTB,11),padding=(10,5))
        s.configure('TEntry',fieldbackground=COLORS['input'],foreground=COLORS['text'],insertcolor=COLORS['text'],bordercolor=COLORS['border'],lightcolor=COLORS['input'],darkcolor=COLORS['input'],padding=8)
        s.map('TEntry',bordercolor=[('focus',COLORS['accent'])])
        s.configure('TCombobox',fieldbackground=COLORS['input'],background=COLORS['input'],foreground=COLORS['text'],arrowcolor=COLORS['muted'],bordercolor=COLORS['border'],padding=8)
        s.map('TCombobox',fieldbackground=[('readonly',COLORS['input'])],foreground=[('readonly',COLORS['text'])],bordercolor=[('focus',COLORS['accent'])])
        s.configure('Accent.TButton',background=COLORS['accent'],foreground=COLORS['white'],font=(FONTB,12),padding=(14,10),borderwidth=0)
        s.map('Accent.TButton',background=[('disabled','#333d57'),('pressed',COLORS['accent']),('active',COLORS['hover'])],foreground=[('disabled',COLORS['muted2'])])
        s.configure('Stop.TButton',background=COLORS['red_bg'],foreground=COLORS['red_text'],font=(FONTB,12),padding=(14,10),borderwidth=0)
        s.map('Stop.TButton',background=[('disabled',COLORS['panel2']),('active','#4a1b24')],foreground=[('disabled',COLORS['muted2'])])
        s.configure('Ghost.TButton',background=COLORS['panel2'],foreground=COLORS['text'],font=(FONTB,11),padding=(10,8),borderwidth=1,relief='flat',bordercolor=COLORS['border'])
        s.map('Ghost.TButton',background=[('active',COLORS['border_soft'])])
        s.configure('Proxy.TButton',background='#232e52',foreground='#dfe4ff',font=(FONTB,11),padding=(10,7),borderwidth=1,relief='solid',bordercolor=COLORS['border'])
        s.map('Proxy.TButton',background=[('active',COLORS['accent'])],foreground=[('active',COLORS['white'])])
        s.configure('Stability.TButton',background=COLORS['green_bg'],foreground=COLORS['green_text'],font=(FONTB,11),padding=(8,7),borderwidth=1,relief='solid',bordercolor=COLORS['border'])
        s.map('Stability.TButton',background=[('active','#194030')],foreground=[('active',COLORS['white'])])
        s.configure('TCheckbutton',background=COLORS['panel'],foreground=COLORS['text'],font=(FONT,11))
        s.map('TCheckbutton',background=[('active',COLORS['panel'])],foreground=[('disabled',COLORS['muted2'])])
        s.configure('TSeparator',background=COLORS['border'])
        s.configure('Treeview',background=COLORS['panel3'],fieldbackground=COLORS['panel3'],foreground=COLORS['text'],rowheight=46,font=(FONT,11),borderwidth=0)
        s.configure('Treeview.Heading',background=COLORS['panel2'],foreground=COLORS['muted'],font=(FONTB,11),padding=10,relief='flat')
        s.map('Treeview.Heading',background=[('active',COLORS['border_soft'])])
        s.map('Treeview',background=[('selected',COLORS['accent'])],foreground=[('selected',COLORS['white'])])
        s.configure('Vertical.TScrollbar',background=COLORS['panel2'],troughcolor=COLORS['panel'],bordercolor=COLORS['panel'],arrowcolor=COLORS['muted'])
        s.configure('Horizontal.TScrollbar',background=COLORS['panel2'],troughcolor=COLORS['panel'],bordercolor=COLORS['panel'],arrowcolor=COLORS['muted'])
        s.configure('Horizontal.TProgressbar',troughcolor=COLORS['panel3'],background=COLORS['accent'],borderwidth=0,lightcolor=COLORS['accent'],darkcolor=COLORS['accent'],thickness=10)
        # Hand cursor for every button-like widget.
        self.root.option_add('*TButton*cursor','hand2'); self.root.option_add('*TCheckbutton*cursor','hand2'); self.root.option_add('*TCombobox*cursor','hand2')
        # Цвет значка подбирается под фон/стиль кнопки, на которой он стоит — так он
        # всегда хорошо виден (см. _set_btn_icon ниже, вызывается при создании каждой
        # кнопки с иконкой, а для вкладок — ещё и при переключении, т.к. их стиль
        # меняется местами Accent/Ghost).
        self._ICON_COLOR_BY_KIND = {'accent':COLORS['white'], 'stop':COLORS['red_text'], 'ghost':COLORS['accent']}
        self._icon_refs = {}

    def _set_btn_icon(self,btn,name,kind,size=20):
        """Ставит на кнопку `btn` настоящий значок `name` (см. _ICON_DRAW) цветом,
        подходящим под стиль `kind` ('accent'/'stop'/'ghost'). Отдельно рисуется
        приглушённая версия того же значка для состояния disabled — иначе Tk сам
        накладывает на картинку грубый штрихованный узор, когда кнопка неактивна
        (например, «Остановить» до начала сканирования). Если Pillow недоступен —
        ничего не делает, кнопка остаётся как была (текст), без ошибок."""
        color = self._ICON_COLOR_BY_KIND.get(kind, COLORS['text'])
        img = _make_icon(name, color, size)
        if img is None:
            return
        dis_img = _make_icon(name, COLORS['muted2'], size)
        self._icon_refs[btn] = (img, dis_img)  # tkinter не хранит картинку сама — нужна живая ссылка
        if dis_img is not None:
            btn.configure(image=(img, 'disabled', dis_img), compound='left')
        else:
            btn.configure(image=img, compound='left')

    def _card(self,parent,row,column,icon,title,columnspan=1,inner_cols=2,accent=None):
        """A visually self-contained settings/results "card": a thin coloured accent
        strip on the left, a panel background, and an icon+title header row. Returns
        the inner content frame (already past the header) so callers can grid their own
        fields starting at row=1 inside it."""
        outer=ttk.Frame(parent,style='Panel.TFrame'); outer.grid(row=row,column=column,columnspan=columnspan,sticky='nsew')
        outer.columnconfigure(1,weight=1); outer.rowconfigure(0,weight=1)
        tk.Frame(outer,bg=accent or COLORS['accent'],width=3).grid(row=0,column=0,sticky='ns')
        inner=ttk.Frame(outer,style='Panel.TFrame',padding=(17,15,17,16)); inner.grid(row=0,column=1,sticky='nsew')
        for c in range(inner_cols): inner.columnconfigure(c,weight=1)
        head=ttk.Frame(inner,style='Panel.TFrame'); head.grid(row=0,column=0,columnspan=inner_cols,sticky='ew',pady=(0,13))
        ttk.Label(head,text=icon,style='CardIcon.TLabel').pack(side='left')
        ttk.Label(head,text=title,style='CardTitle.TLabel').pack(side='left',padx=(8,0))
        return inner

    def _build_ui(self):
        root=ttk.Frame(self.root,padding=(22,20,22,16)); root.pack(fill='both',expand=True)
        root.columnconfigure(0,weight=1)
        root.rowconfigure(0,weight=0)  # персистентная шапка: заголовок + переключатель вкладок
        root.rowconfigure(1,weight=1)  # содержимое текущей вкладки, занимает всё остальное

        # ---------- персистентная шапка (видна на обеих вкладках) ----------
        self.header=header=ttk.Frame(root); header.grid(row=0,column=0,sticky='ew',pady=(0,16)); header.columnconfigure(0,weight=1)
        ttk.Label(header,text='📡  Telegram Proxy Scanner',style='Title.TLabel').grid(row=0,column=0,sticky='w')
        # Подзаголовок переносится по словам (wraplength) — в узком режиме окна (см.
        # _relayout) wraplength уменьшается, иначе одна длинная строка текста сама по
        # себе не даёт сузить окно сильнее, чем её ширина в один ряд.
        self.subtitle_label=ttk.Label(header,text='Поиск, проверка через настоящий Telegram-протокол и подключение к рабочим MTProto-прокси',style='Subtitle.TLabel',wraplength=900,justify='left')
        self.subtitle_label.grid(row=1,column=0,sticky='w',pady=(3,0))

        # Переключатель вкладок — две кнопки сверху справа (как и просили). Активная
        # вкладка подсвечена акцентным стилем, неактивная — обычным "ghost"-стилем.
        tabbar=ttk.Frame(header); tabbar.grid(row=0,column=1,rowspan=2,sticky='e')
        self.tab_scan_btn=ttk.Button(tabbar,text='Сканирование',compound='left',command=lambda:self._show_tab('scan')); self.tab_scan_btn.grid(row=0,column=0,padx=(0,6))
        self.tab_settings_btn=ttk.Button(tabbar,text='Настройка',compound='left',command=lambda:self._show_tab('settings')); self.tab_settings_btn.grid(row=0,column=1)
        # Названия значков для каждой вкладочной кнопки — запоминаем, чтобы при
        # переключении вкладки (_show_tab) перекрасить значок под новый стиль кнопки
        # (активная вкладка — Accent, белый значок; неактивная — Ghost, акцентный цвет).
        self._tab_icon_names={self.tab_scan_btn:'search', self.tab_settings_btn:'gear'}
        # Каждая кнопка хранит и полную, и короткую подпись — в узком режиме окна (см.
        # _relayout) подписи сокращаются, чтобы ничего не обрезалось за краем окна.
        self._action_labels={}
        self._action_labels[self.tab_scan_btn]=('Сканирование','Скан.')
        self._action_labels[self.tab_settings_btn]=('Настройка','Наст.')

        # ---------- контейнер вкладок: обе "страницы" занимают одну и ту же ячейку сетки,
        # видна только та, что поднята наверх (tkraise) — переключение мгновенное и не
        # требует перестройки layout. ----------
        tabs=ttk.Frame(root); tabs.grid(row=1,column=0,sticky='nsew'); tabs.columnconfigure(0,weight=1); tabs.rowconfigure(0,weight=1)
        self._build_tab_settings(tabs)
        self._build_tab_scan(tabs)
        self.tab_settings_frame.grid(row=0,column=0,sticky='nsew')
        self.tab_scan_frame.grid(row=0,column=0,sticky='nsew')

        self._sync_enhanced_availability()
        self._tab_current=None
        self._show_tab('scan')

        # Адаптивность под размер окна: при сужении ниже RESPONSIVE_BREAKPOINT_WIDTH
        # карточки параметров встают друг под друга, подписи кнопок сокращаются, а
        # подзаголовок переносится по словам — чтобы ничего не обрезалось по краю.
        # Если по высоте не хватает места на вкладке "Настройка" (две карточки) — она
        # не раздувает окно сама и не обрезается, а получает свой скроллбар (см. ниже).
        self._layout_narrow=None
        self.root.bind('<Configure>',self._relayout)
        self.root.after_idle(self._relayout)

    def _build_tab_settings(self,parent):
        """Вкладка "Настройка": сохранение/загрузка настроек сверху + обе карточки
        параметров в прокручиваемой области (на случай нехватки высоты окна — см.
        _relayout)."""
        self.tab_settings_frame=f=ttk.Frame(parent)
        f.columnconfigure(0,weight=1); f.columnconfigure(1,weight=0); f.rowconfigure(1,weight=1)

        self.settings_toolbar=toolbar=ttk.Frame(f); toolbar.grid(row=0,column=0,columnspan=2,sticky='ew',pady=(0,14))
        self.save_settings_btn=ttk.Button(toolbar,text='Сохранить настройки',compound='left',style='Ghost.TButton',command=lambda:self.save_settings(silent=False)); self.save_settings_btn.grid(row=0,column=0,padx=(0,8))
        self._set_btn_icon(self.save_settings_btn,'save','ghost')
        self._action_labels[self.save_settings_btn]=('Сохранить настройки','Сохр.')
        ToolTip(self.save_settings_btn,'Сохранить текущие настройки в файл — при следующем запуске они подгрузятся автоматически.')
        self.load_settings_btn=ttk.Button(toolbar,text='Загрузить настройки',compound='left',style='Ghost.TButton',command=lambda:self.load_settings(silent=False)); self.load_settings_btn.grid(row=0,column=1)
        self._set_btn_icon(self.load_settings_btn,'folder','ghost')
        self._action_labels[self.load_settings_btn]=('Загрузить настройки','Загр.')
        ToolTip(self.load_settings_btn,'Перечитать файл настроек вручную (например, если вы поправили его руками).')

        self.settings_canvas=tk.Canvas(f,bg=COLORS['bg'],highlightthickness=0)
        self.settings_canvas.grid(row=1,column=0,sticky='new')
        self.settings_scroll=ttk.Scrollbar(f,orient='vertical',command=self.settings_canvas.yview)
        self.settings_canvas.configure(yscrollcommand=self.settings_scroll.set)
        self.params=params=ttk.Frame(self.settings_canvas); params.columnconfigure(0,weight=1); params.columnconfigure(1,weight=1)
        self._settings_window=self.settings_canvas.create_window((0,0),window=params,anchor='nw')
        self.settings_canvas.bind('<Configure>',lambda e:self.settings_canvas.itemconfigure(self._settings_window,width=e.width))
        params.bind('<Configure>',lambda e:self.settings_canvas.configure(scrollregion=self.settings_canvas.bbox('all')))
        def _settings_mousewheel(event):
            self.settings_canvas.yview_scroll(int(-1*(event.delta/120)),'units')
        self.settings_canvas.bind('<Enter>',lambda e:self.settings_canvas.bind_all('<MouseWheel>',_settings_mousewheel))
        self.settings_canvas.bind('<Leave>',lambda e:self.settings_canvas.unbind_all('<MouseWheel>'))

        self.country=tk.StringVar(value='Все страны'); self.provider=tk.StringVar(value='Все провайдеры')
        self.limit_var=tk.StringVar(value='10'); self.max_ping_var=tk.StringVar(value='1000'); self.interval_var=tk.StringVar(value='1.0')
        self.dynamic_sources=tk.BooleanVar(value=False); self.dynamic_target_var=tk.StringVar(value='40'); self.concurrency_var=tk.StringVar(value='64')
        self.enhanced_search=tk.BooleanVar(value=False); self.discovery_time_var=tk.StringVar(value='25')
        self.topup_rounds_var=tk.StringVar(value=str(MAX_TOPUP_ROUNDS))
        # v30: четыре независимые галочки видов прокси вместо одной «другие виды прокси»
        self.ptype_vars={t:tk.BooleanVar(value=(t=='mtproto')) for t in PROXY_TYPES}
        self.tg_gateways=tk.BooleanVar(value=True)
        self.github_token_var=tk.StringVar(value='')
        self.telegram_proxy_var=tk.StringVar(value='')
        self.auto_ping=tk.BooleanVar(value=True); self.only_ok=tk.BooleanVar(value=False)
        self.stability_enabled=tk.BooleanVar(value=False); self.stability_seconds_var=tk.StringVar(value='3')
        self.lock_order=tk.BooleanVar(value=False); self._order_counter=0

        # Карточка 1 — источники (фильтрация результатов перенесена на вкладку
        # "Сканирование" — пункт №2 обращения v29: "в блоке настроек оставить
        # исключительно настройки"; Страна/Провайдер/Скрывать offline не влияют на то,
        # ЧТО сканируется, только на то, что из уже найденного показывается, поэтому это
        # фильтры результатов, а не настройки сканирования, и логичнее жить рядом с самой
        # таблицей результатов).
        card1=self._card(params,0,0,'🔎','Источники',accent=COLORS['blue'])
        self._entry(card1,2,0,'Нужно прокси',self.limit_var,'шт.',help_text='Сколько рабочих прокси нужно найти и показать в списке. Поиск продолжится, пока не наберётся это количество (или пока не закончатся источники/кандидаты).')
        self._entry(card1,2,1,'Макс. ping',self.max_ping_var,'ms',help_text='Прокси с задержкой (ping) выше этого значения не попадают в список результатов. Это же значение теперь используется и как порог проверки стабильности (см. карточку «Автоматика и производительность»).')
        ttk.Separator(card1,orient='horizontal').grid(row=3,column=0,columnspan=2,sticky='ew',pady=(13,11))
        ttk.Label(card1,text='Поиск источников в интернете',style='Caption.TLabel').grid(row=4,column=0,columnspan=2,sticky='w',pady=(0,7))
        self._check(card1,5,0,'Динамический поиск источников',self.dynamic_sources,command=self._on_dynamic_toggle,help_text='Встроенный список источников НЕ используется — вместо него сканер сам найдёт свежие списки прокси на GitHub за несколько секунд (см. «Источников (авто)» ниже; жёсткий лимит времени не даёт поиску растянуться на часы).',padx=(0,0))
        self.enhanced_search_chk=self._check(card1,5,1,'Улучшенный поиск',self.enhanced_search,command=self.sync_settings,help_text='Доступно только при включённом «Динамический поиск источников». Сканер дополнительно ищет источники не только на GitHub, но и среди открытых тг-каналов, сайтов и форумов, где публикуют прокси-ссылки — через проверенный seed-список плюс живой веб-поиск. Это немного дольше, но даёт более разнообразные источники.',padx=(0,0))
        self._entry(card1,6,0,'Источников (авто)',self.dynamic_target_var,'шт.',help_text='Сколько источников списков прокси попытаться найти автоматически в интернете. Чем больше — тем больше кандидатов на прокси в итоге получится (время поиска при этом задаётся отдельным параметром справа, не этим).')
        self._entry(card1,6,1,'Время поиска',self.discovery_time_var,'сек.',help_text='Жёсткий лимит времени (в секундах, от 5 до 600 — т.е. до 10 минут) на поиск источников — задаётся отдельно от «Источников (авто)». Поиск останавливается по истечении этого времени, даже если нужное количество источников ещё не набралось; либо раньше, если набралось. Больше времени — выше шанс найти все запрошенные источники (в т.ч. пережить временный лимит запросов GitHub), но и дольше ждать.')
        self._entry(card1,7,0,'Попыток дозапроса',self.topup_rounds_var,'раз',help_text='Если при включённом динамическом поиске рабочих прокси набралось меньше, чем указано в «Нужно прокси», программа ищет ЕЩЁ источники (не повторяя уже проверенные) и проверяет новые прокси из них. Это число — сколько раз повторить такой дозапрос, прежде чем остановиться с тем, что нашлось. 0 — дозапрос отключён, один проход.')
        gh_box=ttk.Frame(card1,style='Panel.TFrame'); gh_box.grid(row=7,column=1,sticky='ew',pady=(0,10)); gh_box.columnconfigure(0,weight=1)
        gh_cap=ttk.Frame(gh_box,style='Panel.TFrame'); gh_cap.grid(row=0,column=0,sticky='w',pady=(0,5)); ttk.Label(gh_cap,text='GitHub token',style='Muted.TLabel').pack(side='left')
        self._help_badge(gh_cap,'Необязательно. Поиск источников на GitHub без входа ограничен ~10 запросами в минуту НА ВСЕХ пользователей интернета сразу — отсюда задержки при динамическом/улучшенном поиске и особенно при дозапросе. Личный токен GitHub (создаётся на github.com → Settings → Developer settings → Personal access tokens; права/scope не нужны — токен нужен только для аутентификации запроса) поднимает лимит примерно до 30 запросов в минуту. Без токена всё работает как раньше, просто медленнее при частых сканированиях подряд.').pack(side='left',padx=(5,0))
        ttk.Entry(gh_box,textvariable=self.github_token_var,width=22,show='•').grid(row=1,column=0,sticky='ew')
        ttk.Separator(card1,orient='horizontal').grid(row=8,column=0,columnspan=2,sticky='ew',pady=(13,11))
        ttk.Label(card1,text='Виды прокси для поиска',style='Caption.TLabel').grid(row=9,column=0,columnspan=2,sticky='w',pady=(0,7))
        types_row=ttk.Frame(card1,style='Panel.TFrame'); types_row.grid(row=10,column=0,columnspan=2,sticky='w')
        _type_help={
            'mtproto':'Основной вид для Telegram: список MTProto-прокси ищется в готовых/найденных источниках и тг-каналах; проверка — настоящее MTProto-рукопожатие (в том числе FakeTLS).',
            'socks5':'Ищутся готовые и найденные списки SOCKS5; проверка — полное рукопожатие протокола и CONNECT до core.telegram.org. Подключение в Telegram Desktop в один клик (tg://socks). Бесплатных SOCKS5 мало, и многие недоступны из-за блокировок.',
            'http':'Ищутся списки HTTP-прокси; проверка — CONNECT до core.telegram.org. У HTTP нет готовой ссылки подключения в Telegram (ограничение самого Telegram) — показывается адрес для ручной настройки.',
            'web':'Ищутся ссылки tg://webproxy (новый тип Telegram). Публичных списков почти нет — ссылки берутся из тг-каналов и найденных страниц (удобнее с динамическим/улучшенным поиском). Проверка — настоящее TLS-рукопожатие и HTTPS-запрос; сам «мост» Telegram не документирует, поэтому глубже честно не проверяется.',
        }
        for _ci,_t in enumerate(PROXY_TYPES):
            self._check(types_row,0,_ci,PTYPE_LABELS[_t],self.ptype_vars[_t],command=self.sync_settings,help_text=_type_help[_t],padx=(0,14))
        ttk.Label(card1,text='Ищутся, проверяются и показываются только отмеченные виды. Для каждого — свои источники и свой поиск.',style='Muted.TLabel',wraplength=460,justify='left').grid(row=11,column=0,columnspan=2,sticky='w',pady=(0,2))
        ttk.Separator(card1,orient='horizontal').grid(row=12,column=0,columnspan=2,sticky='ew',pady=(13,11))
        tp_box=ttk.Frame(card1,style='Panel.TFrame'); tp_box.grid(row=13,column=0,columnspan=2,sticky='ew',pady=(0,10)); tp_box.columnconfigure(0,weight=1)
        tp_cap=ttk.Frame(tp_box,style='Panel.TFrame'); tp_cap.grid(row=0,column=0,sticky='w',pady=(0,5)); ttk.Label(tp_cap,text='Рабочий прокси или шлюз для Telegram-источников',style='Muted.TLabel').pack(side='left')
        self._help_badge(tp_cap,'Необязательно. Нужно, если домен t.me недоступен напрямую с вашей сети, а Telegram у вас работает только через MTProto-прокси. ВАЖНО: MTProto-прокси пересылает лишь протокол Telegram и технически не может открыть веб-страницу t.me/s/канал, поэтому именно он сюда не подходит. Программа сама пробует обходные маршруты (см. галочку ниже), а здесь можно задать свой: (1) SOCKS5/HTTP-прокси — tg://socks?server=...&port=..., socks5://[логин:пароль@]хост:порт, http://[логин:пароль@]хост:порт или «хост:порт» (= SOCKS5); (2) шаблон своего шлюза — адрес вашего сервиса со вставкой {urlenc} (адрес страницы канала, закодированный), {url} (как есть) или {ch} (имя канала), например https://мой-сервер/fetch?u={urlenc}. GitHub и другие источники через это поле не идут — только чтение тг-каналов.').pack(side='left',padx=(5,0))
        ttk.Entry(tp_box,textvariable=self.telegram_proxy_var,width=46).grid(row=1,column=0,sticky='ew')
        gw_wrap=ttk.Frame(tp_box,style='Panel.TFrame'); gw_wrap.grid(row=2,column=0,sticky='w',pady=(8,0))
        self._check(gw_wrap,0,0,'Обходить блокировку t.me через зеркала и публичные шлюзы',self.tg_gateways,command=self.sync_settings,help_text='Если t.me недоступен напрямую, программа по очереди пробует: официальные псевдонимы домена (telegram.me, telegram.dog, tx.me), затем публичные сервисы-«читалки» (r.jina.ai, allorigins, codetabs, corsproxy.io, RSSHub), которые сами скачивают публичную страницу канала и отдают её вам — для вашей сети это обычный запрос к стороннему сайту, а не к Telegram. Каждый ответ проверяется по содержимому (должны быть настоящие посты). Наружу уходит только имя ПУБЛИЧНОГО канала. Не поможет, если заблокированы все адреса Telegram и недоступны сами шлюзы — тогда поиск идёт по GitHub и сайтам. Снимите галочку, если не хотите обращаться к сторонним сервисам.',padx=(0,0))

        self.card1_outer=card1.master

        # Карточка 2 — автоматика и производительность
        card2=self._card(params,0,1,'⚙️','Автоматика и производительность',accent=COLORS['accent2'])
        self._entry(card2,1,0,'Параллельность проверок',self.concurrency_var,'потоков',help_text='Сколько прокси проверяются одновременно (в сумме для всех видов проверки — TCP/MTProto, стабильность, geo). Меньше значение — медленнее сканирование, но меньше нагрузка на ваш интернет-канал; полезно на слабом или нестабильном интернете. Больше значение — быстрее на хорошем канале.')
        self._entry(card2,1,1,'Интервал ping',self.interval_var,'сек.',help_text='Как часто (в секундах) автопроверка обновляет пинг уже показанных прокси.')
        self._check(card2,2,0,'Автопроверка ping',self.auto_ping,command=self.sync_settings,help_text='Раз в «Интервал ping» секунд заново проверяет пинг уже найденных прокси из списка, чтобы видеть, если какой-то из них отвалился.',padx=(0,0))
        ttk.Separator(card2,orient='horizontal').grid(row=3,column=0,columnspan=2,sticky='ew',pady=(13,11))
        ttk.Label(card2,text='Проверка стабильности перед выдачей прокси',style='Caption.TLabel').grid(row=4,column=0,columnspan=2,sticky='w',pady=(0,7))
        self._check(card2,5,0,'Проверка стабильности',self.stability_enabled,command=self.sync_settings,help_text='Перед тем как показать прокси в списке, сканер держит с ним одно соединение (или для SOCKS5/HTTP/WEB — повторяет полную проверку) и гоняет через него настоящий Telegram-трафик каждые 0.5 сек в течение указанного времени. Если хоть раз пинг поднимется выше «Макс. ping» (см. выше) — прокси отбрасывается и в список не попадает. ИСПРАВЛЕНО в v28: раньше здесь был отдельный, не связанный с «Макс. ping» зашитый порог 100 мс — из-за него дозапрос находил новые источники, но почти все их прокси всё равно браковались на этом шаге, даже если «Макс. ping» был указан гораздо выше.',padx=(0,0))
        self._entry(card2,5,1,'Секунд',self.stability_seconds_var,'сек.',help_text='Сколько секунд длится проверка стабильности одного прокси.')
        self._check(card2,6,0,'Зафиксировать порядок',self.lock_order,command=self.render_current,help_text='Не переставлять строки местами при обновлении пинга — удобно, если вы наводите курсор на список во время автопроверки.',padx=(0,0))
        ttk.Label(card2,text='Ping выше «Макс. ping» в любой момент — прокси сразу отсеивается.',style='Muted.TLabel',wraplength=230,justify='left').grid(row=6,column=1,sticky='w',pady=(3,0))
        self.card2_outer=card2.master

    def _build_tab_scan(self,parent):
        """Вкладка "Сканирование": лог/экспорт/скан/стоп, статистика, таблица
        результатов на всю оставшуюся высоту вкладки и подвал с прогрессом."""
        self.tab_scan_frame=f=ttk.Frame(parent)
        f.columnconfigure(0,weight=1)
        f.rowconfigure(0,weight=0); f.rowconfigure(1,weight=0); f.rowconfigure(2,weight=1); f.rowconfigure(3,weight=0)

        toolbar=ttk.Frame(f); toolbar.grid(row=0,column=0,sticky='ew',pady=(0,14))
        self.log_btn=ttk.Button(toolbar,text='Лог',compound='left',style='Ghost.TButton',command=self.open_log); self.log_btn.grid(row=0,column=0,padx=(0,5))
        self._set_btn_icon(self.log_btn,'document','ghost')
        self._action_labels[self.log_btn]=('Лог','Лог')
        ToolTip(self.log_btn,'Открыть подробный технический журнал работы программы (для диагностики проблем).')
        self.export_btn=ttk.Button(toolbar,text='Экспорт',compound='left',style='Ghost.TButton',command=self.export); self.export_btn.grid(row=0,column=1,padx=(0,5))
        self._set_btn_icon(self.export_btn,'download','ghost')
        self._action_labels[self.export_btn]=('Экспорт','Эксп.')
        ToolTip(self.export_btn,'Сохранить текущий список найденных прокси в файл.')
        ttk.Separator(toolbar,orient='vertical').grid(row=0,column=2,sticky='ns',padx=6)
        self.scan_btn=ttk.Button(toolbar,text='Сканировать',compound='left',style='Accent.TButton',command=self.start); self.scan_btn.grid(row=0,column=3,padx=(0,8))
        self._set_btn_icon(self.scan_btn,'play','accent')
        self._action_labels[self.scan_btn]=('Сканировать','Скан')
        self.stop_btn=ttk.Button(toolbar,text='Остановить',compound='left',style='Stop.TButton',command=self.stop,state='disabled'); self.stop_btn.grid(row=0,column=4)
        self._set_btn_icon(self.stop_btn,'stop','stop')
        self._action_labels[self.stop_btn]=('Остановить','Стоп')

        # ---------- stat cards ----------
        self.stats=stats=ttk.Frame(f); stats.grid(row=1,column=0,sticky='ew',pady=(0,14)); [stats.columnconfigure(c,weight=1) for c in range(4)]
        self.stat_found=self._stat(stats,0,'📦','КАНДИДАТОВ','0','blue')
        self.stat_online=self._stat(stats,1,'✅','РАБОЧИХ','0','green')
        self.stat_visible=self._stat(stats,2,'👁','ПОКАЗАНО','0','accent2')
        self.stat_ping=self._stat(stats,3,'⚡','СРЕДНИЙ PING','—','yellow')

        # ---------- results card — занимает всю оставшуюся высоту вкладки (вес 1),
        # как и просили: "таблица результатов на всю страницу" ----------
        rp_outer=ttk.Frame(f,style='Panel.TFrame'); rp_outer.grid(row=2,column=0,sticky='nsew'); rp_outer.columnconfigure(1,weight=1); rp_outer.rowconfigure(0,weight=1)
        tk.Frame(rp_outer,bg=COLORS['green'],width=3).grid(row=0,column=0,sticky='ns')
        rp=ttk.Frame(rp_outer,style='Panel.TFrame',padding=(17,15,17,16)); rp.grid(row=0,column=1,sticky='nsew'); rp.rowconfigure(2,weight=1); rp.columnconfigure(0,weight=1)
        rtop=ttk.Frame(rp,style='Panel.TFrame'); rtop.grid(row=0,column=0,sticky='ew',pady=(0,11)); rtop.columnconfigure(1,weight=1)
        head=ttk.Frame(rtop,style='Panel.TFrame'); head.grid(row=0,column=0,sticky='w')
        ttk.Label(head,text='📋',style='CardIcon.TLabel').pack(side='left'); ttk.Label(head,text='Результаты',style='CardTitle.TLabel').pack(side='left',padx=(8,0))
        self.status=ttk.Label(rtop,text='Готово',style='StatusPill.TLabel'); self.status.grid(row=0,column=2,sticky='e')

        # ---------- компактная фильтрация результатов (пункт №2 обращения v29:
        # "фильтрацию перенести на страницу сканирования... в блоке настроек оставить
        # исключительно настройки") — Страна/Провайдер/Скрывать offline раньше жили на
        # вкладке "Настройка"; это фильтры уже НАЙДЕННОГО списка (апдейтят сразу
        # render() через apply_filters), а не параметры самого сканирования, поэтому
        # логичнее держать их прямо над таблицей, которую они фильтруют — и компактно,
        # в одну строку, без подписей-заголовков и плашек-подсказок, как в карточках
        # настроек. ---------- #
        fbar=ttk.Frame(rp,style='Panel.TFrame'); fbar.grid(row=1,column=0,sticky='ew',pady=(0,9))
        ttk.Label(fbar,text='Фильтр:',style='Muted.TLabel').pack(side='left',padx=(0,6))
        self.country_cb=ttk.Combobox(fbar,textvariable=self.country,values=['Все страны'],state='readonly',width=14)
        self.country_cb.pack(side='left',padx=(0,6)); self.country_cb.bind('<<ComboboxSelected>>',lambda e:self.apply_filters())
        self.provider_cb=ttk.Combobox(fbar,textvariable=self.provider,values=['Все провайдеры'],state='readonly',width=17)
        self.provider_cb.pack(side='left',padx=(0,10)); self.provider_cb.bind('<<ComboboxSelected>>',lambda e:self.apply_filters())
        ttk.Checkbutton(fbar,text='Скрывать offline',variable=self.only_ok,command=self.apply_filters).pack(side='left')

        self.table=ttk.Frame(rp,style='Panel.TFrame'); table=self.table; table.grid(row=2,column=0,sticky='nsew'); table.rowconfigure(0,weight=1); table.columnconfigure(0,weight=1)
        cols=('type','country','provider','host','port','ping','source','status'); self.tree=ttk.Treeview(table,columns=cols,show='headings',selectmode='extended'); heads={'type':'Тип','country':'Страна','provider':'Провайдер / ASN','host':'Сервер','port':'Порт','ping':'Ping','source':'Источник','status':'Статус'}
        for c in cols:self.tree.heading(c,text=heads[c])
        widths={'type':78,'country':150,'provider':220,'host':240,'port':65,'ping':90,'source':105,'status':185}
        for c,w in widths.items():self.tree.column(c,width=w,minwidth=70 if c=='type' else (90 if c!='country' else 120),stretch=c in ('provider','host','status'),anchor='w' if c not in ('port','ping','type') else 'center')
        self.tree.tag_configure('good',background=COLORS['green_bg'],foreground=COLORS['green_text'])
        self.tree.tag_configure('slow',background=COLORS['yellow_bg'],foreground=COLORS['yellow_text'])
        self.tree.tag_configure('bad',background=COLORS['red_bg'],foreground=COLORS['red_text'])
        ys=ttk.Scrollbar(table,orient='vertical',command=self.tree.yview); xs=ttk.Scrollbar(table,orient='horizontal',command=self.tree.xview)
        self.tree.configure(yscrollcommand=ys.set,xscrollcommand=xs.set)
        self.tree.grid(row=0,column=0,columnspan=2,sticky='nsew'); ys.grid(row=0,column=2,sticky='ns'); xs.grid(row=1,column=0,columnspan=2,sticky='ew'); self.tree.bind('<ButtonRelease-1>',self.row_click); self.tree.bind('<Double-1>',self.row_action)

        self.footer=footer=ttk.Frame(f); footer.grid(row=3,column=0,sticky='ew',pady=(12,0)); footer.columnconfigure(0,weight=1)
        self.progress=ttk.Progressbar(footer,mode='determinate'); self.progress.grid(row=0,column=0,sticky='ew'); self.progress_label=ttk.Label(footer,text='Готово',style='Sub.TLabel'); self.progress_label.grid(row=0,column=1,padx=(12,0)); self.count_label=ttk.Label(footer,text='0 / 10',style='Sub.TLabel'); self.count_label.grid(row=0,column=2,padx=(12,0))
        ttk.Label(footer,text='Одинарный клик — выбрать строку. Двойной клик по прокси — подключиться через Telegram Desktop.',style='Sub.TLabel').grid(row=1,column=0,columnspan=3,sticky='w',pady=(7,0))

    def _show_tab(self,name):
        self._tab_current=name
        if name=='scan':
            self.tab_scan_frame.tkraise()
            self.tab_scan_btn.configure(style='Accent.TButton'); self.tab_settings_btn.configure(style='Ghost.TButton')
        else:
            self.tab_settings_frame.tkraise()
            self.tab_settings_btn.configure(style='Accent.TButton'); self.tab_scan_btn.configure(style='Ghost.TButton')
            self.settings_canvas.yview_moveto(0)
        # Активная вкладка подсвечена акцентным стилем — значок на ней перекрашивается
        # в белый (как и текст), на неактивной (ghost-стиль) — обратно в акцентный цвет.
        active=self.tab_scan_btn if name=='scan' else self.tab_settings_btn
        inactive=self.tab_settings_btn if name=='scan' else self.tab_scan_btn
        self._set_btn_icon(active,self._tab_icon_names[active],'accent')
        self._set_btn_icon(inactive,self._tab_icon_names[inactive],'ghost')

    def _relayout(self,event=None):
        try:
            width=self.root.winfo_width()
        except Exception:
            return
        if width<=1: return  # окно ещё не отрисовано — геометрия пока не окончательная
        narrow=width<RESPONSIVE_BREAKPOINT_WIDTH
        if narrow!=self._layout_narrow:
            self._layout_narrow=narrow
            if narrow:
                self.card1_outer.grid(row=0,column=0,columnspan=2,sticky='nsew',pady=(0,10))
                self.card2_outer.grid(row=1,column=0,columnspan=2,sticky='nsew',pady=(0,0))
                self.subtitle_label.configure(wraplength=480)
            else:
                self.card1_outer.grid(row=0,column=0,columnspan=1,sticky='nsew',pady=(0,0))
                self.card2_outer.grid(row=0,column=1,columnspan=1,sticky='nsew',pady=(0,0))
                self.subtitle_label.configure(wraplength=900)
            for btn,(long_text,short_text) in self._action_labels.items():
                btn.config(text=(short_text if narrow else long_text))
        # Вкладка "Настройка" (карточки параметров) не раздувает окно сама и не
        # обрезается, если высоты не хватает — получает ровно столько высоты, сколько
        # можно выделить, не трогая шапку и панель сохранения/загрузки, а то, что не
        # поместилось, становится доступно прокруткой (колесо мыши или скроллбар,
        # который показывается только когда он реально нужен). На вкладке
        # "Сканирование" результаты и так сами занимают всё свободное место (вес 1,
        # "на всю страницу", как и просили) — своей прокрутки им не нужно, таблица
        # умеет прокручиваться сама.
        self.root.update_idletasks()
        params_reqh=self.params.winfo_reqheight()
        toolbar_reqh=self.settings_toolbar.winfo_reqheight()
        window_h=self.root.winfo_height(); header_reqh=self.header.winfo_reqheight()
        avail=window_h-header_reqh-toolbar_reqh-SETTINGS_VERTICAL_CHROME
        if avail>=params_reqh:
            canvas_h=params_reqh; need_scroll=False
        else:
            canvas_h=max(SETTINGS_CANVAS_MIN_HEIGHT,avail); need_scroll=True
        self.settings_canvas.configure(height=canvas_h)
        self.settings_canvas.configure(scrollregion=self.settings_canvas.bbox('all'))
        if need_scroll:
            self.settings_scroll.grid(row=1,column=1,sticky='ns')
        else:
            self.settings_scroll.grid_remove(); self.settings_canvas.yview_moveto(0)
    def _on_dynamic_toggle(self):
        self._sync_enhanced_availability(); self.sync_settings()

    def _sync_enhanced_availability(self):
        on=bool(self.dynamic_sources.get())
        try: self.enhanced_search_chk.configure(state=('normal' if on else 'disabled'))
        except Exception: pass
        if not on and self.enhanced_search.get(): self.enhanced_search.set(False)

    def _help_badge(self,parent,text):
        size=20
        bg=parent['background'] if 'background' in parent.keys() else COLORS['panel']
        c=tk.Canvas(parent,width=size,height=size,bg=bg,highlightthickness=0,cursor='question_arrow')
        c.create_oval(1,1,size-1,size-1,fill=COLORS['panel3'],outline=COLORS['border'])
        c.create_text(size//2+1,size//2+1,text='?',fill=COLORS['muted'],font=('Segoe UI Semibold',9))
        ToolTip(c,text)
        return c

    def _combo(self,parent,row,col,label,var,values,help_text=None):
        box=ttk.Frame(parent,style='Panel.TFrame'); box.grid(row=row,column=col,sticky='ew',padx=(0,10 if col==0 else 0),pady=(0,10)); box.columnconfigure(0,weight=1)
        cap=ttk.Frame(box,style='Panel.TFrame'); cap.grid(row=0,column=0,sticky='w',pady=(0,5)); ttk.Label(cap,text=label,style='Muted.TLabel').pack(side='left')
        if help_text: self._help_badge(cap,help_text).pack(side='left',padx=(5,0))
        cb=ttk.Combobox(box,textvariable=var,values=values,state='readonly'); cb.grid(row=1,column=0,sticky='ew'); return cb

    def _entry(self,parent,row,col,label,var,suffix,help_text=None):
        box=ttk.Frame(parent,style='Panel.TFrame'); box.grid(row=row,column=col,sticky='ew',padx=(0,10 if col==0 else 0),pady=(0,10)); box.columnconfigure(0,weight=1)
        cap=ttk.Frame(box,style='Panel.TFrame'); cap.grid(row=0,column=0,sticky='w',pady=(0,5)); ttk.Label(cap,text=label,style='Muted.TLabel').pack(side='left')
        if help_text: self._help_badge(cap,help_text).pack(side='left',padx=(5,0))
        line=ttk.Frame(box,style='Panel.TFrame'); line.grid(row=1,column=0,sticky='ew'); line.columnconfigure(0,weight=1)
        ttk.Entry(line,textvariable=var,width=6).grid(row=0,column=0,sticky='ew'); ttk.Label(line,text=suffix,style='Muted.TLabel').grid(row=0,column=1,padx=(7,0))

    def _check(self,parent,row,col,text,var,command=None,help_text=None,padx=(0,18)):
        wrap=ttk.Frame(parent,style='Panel.TFrame'); wrap.grid(row=row,column=col,sticky='w',padx=padx,pady=(0,8))
        cb=ttk.Checkbutton(wrap,text=text,variable=var,command=command); cb.pack(side='left')
        if help_text: self._help_badge(wrap,help_text).pack(side='left',padx=(5,0))
        return cb

    def _stat(self,parent,col,icon,title,value,color_key):
        card=ttk.Frame(parent,style='Panel2.TFrame'); card.grid(row=0,column=col,sticky='ew',padx=(0 if col==0 else 6,0 if col==3 else 6))
        tk.Frame(card,bg=COLORS[color_key],height=3).pack(fill='x',side='top')
        body=ttk.Frame(card,style='Panel2.TFrame',padding=(14,11,14,12)); body.pack(fill='both',expand=True)
        head=ttk.Frame(body,style='Panel2.TFrame'); head.pack(anchor='w')
        ttk.Label(head,text=icon,style='Panel2.TLabel',font=('Segoe UI',10)).pack(side='left')
        ttk.Label(head,text=title,style='MutedAlt.TLabel').pack(side='left',padx=(6,0))
        style_suffix={'blue':'Blue','green':'Green','accent2':'Accent2','yellow':'Yellow'}.get(color_key,'')
        l=ttk.Label(body,text=value,style=f'Value{style_suffix}.TLabel'); l.pack(anchor='w',pady=(5,0)); return l

    def sync_settings(self):
        try: interval=max(.1,min(3600,float(self.interval_var.get().replace(',','.'))))
        except: interval=1.0
        try: limit=max(1,min(500,int(self.limit_var.get())))
        except: limit=10
        try: max_ping=max(1,min(60000,int(float(self.max_ping_var.get().replace(',','.')))))
        except: max_ping=1000
        try: stability_seconds=max(.5,min(120.0,float(self.stability_seconds_var.get().replace(',','.'))))
        except: stability_seconds=3.0
        try: dynamic_target=max(1,min(300,int(self.dynamic_target_var.get())))
        except: dynamic_target=40
        try: concurrency=max(1,min(300,int(self.concurrency_var.get())))
        except: concurrency=64
        try: discovery_time=max(5,min(600,int(float(self.discovery_time_var.get().replace(',','.')))))
        except: discovery_time=25
        try: topup_rounds=max(0,min(5,int(self.topup_rounds_var.get())))
        except: topup_rounds=MAX_TOPUP_ROUNDS
        self.settings.update(interval=interval,limit=limit,max_ping=max_ping,auto_ping=self.auto_ping.get(),only_ok=self.only_ok.get(),country=self.country.get(),provider=self.provider.get(),stability=self.stability_enabled.get(),stability_seconds=stability_seconds,dynamic_target=dynamic_target,concurrency=concurrency,dynamic_sources=self.dynamic_sources.get(),enhanced_search=self.enhanced_search.get(),discovery_time=discovery_time,topup_rounds=topup_rounds,tg_gateways=self.tg_gateways.get(),**{'ptype_'+t:self.ptype_vars[t].get() for t in PROXY_TYPES},github_token=self.github_token_var.get().strip(),telegram_proxy=self.telegram_proxy_var.get().strip())
        self.stability_seconds_var.set(str(stability_seconds).rstrip('0').rstrip('.') if stability_seconds%1 else str(int(stability_seconds)))
        self.interval_var.set(str(interval)); self.limit_var.set(str(limit)); self.max_ping_var.set(str(max_ping)); self.dynamic_target_var.set(str(dynamic_target)); self.concurrency_var.set(str(concurrency)); self.discovery_time_var.set(str(discovery_time)); self.topup_rounds_var.set(str(topup_rounds))
        if self.all_results:self.render(self.all_results)

    def save_settings(self,silent=False):
        self.sync_settings()
        data={'country':self.country.get(),'provider':self.provider.get(),'limit':self.limit_var.get(),
              'max_ping':self.max_ping_var.get(),'interval':self.interval_var.get(),
              'dynamic_sources':self.dynamic_sources.get(),'dynamic_target':self.dynamic_target_var.get(),
              'enhanced_search':self.enhanced_search.get(),'discovery_time':self.discovery_time_var.get(),
              'topup_rounds':self.topup_rounds_var.get(),'tg_gateways':self.tg_gateways.get(),**{'ptype_'+t:self.ptype_vars[t].get() for t in PROXY_TYPES},
              'github_token':self.github_token_var.get().strip(),'telegram_proxy':self.telegram_proxy_var.get().strip(),
              'concurrency':self.concurrency_var.get(),'auto_ping':self.auto_ping.get(),'only_ok':self.only_ok.get(),
              'stability_enabled':self.stability_enabled.get(),'stability_seconds':self.stability_seconds_var.get(),
              'lock_order':self.lock_order.get()}
        try:
            with open(SETTINGS_FILE,'w',encoding='utf-8') as f: json.dump(data,f,ensure_ascii=False,indent=2)
            log(f'SETTINGS SAVED to {SETTINGS_FILE}')
            if not silent: self.status.config(text='Настройки сохранены: '+SETTINGS_FILE)
        except Exception as e:
            log(f'SETTINGS SAVE FAILED: {e}',True)
            if not silent: messagebox.showerror(APP_TITLE,f'Не удалось сохранить настройки:\n{e}')

    def load_settings(self,silent=False):
        if not os.path.exists(SETTINGS_FILE):
            if not silent: messagebox.showinfo(APP_TITLE,'Файл настроек ещё не сохранён — нажмите «Сохранить настройки» после того как всё настроите.')
            return
        try:
            with open(SETTINGS_FILE,'r',encoding='utf-8') as f: data=json.load(f)
        except Exception as e:
            log(f'SETTINGS LOAD FAILED: {e}',True)
            if not silent: messagebox.showerror(APP_TITLE,f'Не удалось загрузить настройки:\n{e}')
            return
        try:
            if 'country' in data: self.country.set(data['country'])
            if 'provider' in data: self.provider.set(data['provider'])
            if 'limit' in data: self.limit_var.set(str(data['limit']))
            if 'max_ping' in data: self.max_ping_var.set(str(data['max_ping']))
            if 'interval' in data: self.interval_var.set(str(data['interval']))
            if 'dynamic_sources' in data: self.dynamic_sources.set(bool(data['dynamic_sources']))
            if 'dynamic_target' in data: self.dynamic_target_var.set(str(data['dynamic_target']))
            if 'enhanced_search' in data: self.enhanced_search.set(bool(data['enhanced_search']))
            if 'discovery_time' in data: self.discovery_time_var.set(str(data['discovery_time']))
            if 'topup_rounds' in data: self.topup_rounds_var.set(str(data['topup_rounds']))
            # v30: миграция — файл от v≤29 хранит одну галочку other_proxy_types
            _en=enabled_types_from_settings(data)
            for _t in PROXY_TYPES: self.ptype_vars[_t].set(_t in _en)
            if 'tg_gateways' in data: self.tg_gateways.set(bool(data['tg_gateways']))
            if 'github_token' in data: self.github_token_var.set(str(data['github_token']))
            if 'telegram_proxy' in data: self.telegram_proxy_var.set(str(data['telegram_proxy']))
            self._sync_enhanced_availability()
            if 'concurrency' in data: self.concurrency_var.set(str(data['concurrency']))
            if 'auto_ping' in data: self.auto_ping.set(bool(data['auto_ping']))
            if 'only_ok' in data: self.only_ok.set(bool(data['only_ok']))
            if 'stability_enabled' in data: self.stability_enabled.set(bool(data['stability_enabled']))
            if 'stability_seconds' in data: self.stability_seconds_var.set(str(data['stability_seconds']))
            if 'lock_order' in data: self.lock_order.set(bool(data['lock_order']))
            self.sync_settings(); self.apply_filters()
            log(f'SETTINGS LOADED from {SETTINGS_FILE}')
            if not silent: self.status.config(text='Настройки загружены: '+SETTINGS_FILE)
        except Exception as e:
            log(f'SETTINGS APPLY FAILED: {e}',True)
            if not silent: messagebox.showerror(APP_TITLE,f'Файл настроек повреждён:\n{e}')

    def start(self):
        if self.scan_running:return
        log('SCAN START requested')
        self.sync_settings()
        if not enabled_types_from_settings(self.settings):
            messagebox.showwarning(APP_TITLE,'Не выбран ни один вид прокси. Отметьте хотя бы один (MTProto, SOCKS5, HTTP или WEB) в настройках, в блоке «Виды прокси для поиска».')
            return
        self.scan_settings=dict(self.settings); self.scan_dynamic_sources=bool(self.dynamic_sources.get()); self.scan_enhanced_search=bool(self.enhanced_search.get()) and self.scan_dynamic_sources; self.clear(); self.stop_event.clear(); self.scan_running=True; self.scan_btn.config(state='disabled'); self.stop_btn.config(state='normal'); self.export_btn.config(state='disabled')
        # См. _progress_heartbeat: во время долгих "тихих" участков проверки (когда много
        # прокси одновременно виснут на таймауте и подряд какое-то время не приходит ни
        # одного тика прогресса) полоса раньше выглядела зависшей, хотя сканирование на
        # самом деле продолжалось — сообщили как баг. Хартбит просто подмигивает подписью,
        # пока реальных тиков нет, визуально подтверждая, что программа жива.
        self._progress_last_tick=time.time(); self._progress_heartbeat_phase=0
        self.root.after(500,self._progress_heartbeat)
        threading.Thread(target=self.scan,daemon=True).start()

    def _progress_heartbeat(self):
        if self.scan_running:
            idle=time.time()-self._progress_last_tick
            # Только в режиме determinate с непустым подписанным текстом "Проверка: N/M" —
            # indeterminate-полоса (загрузка источников) уже анимируется сама по себе.
            if idle>1.5 and str(self.progress['mode'])=='determinate' and self.progress_label.cget('text').startswith('Проверка:'):
                self._progress_heartbeat_phase=(self._progress_heartbeat_phase+1)%4
                base=self.progress_label.cget('text').split(' (ждём ответ')[0]
                dots='.'*self._progress_heartbeat_phase
                self.progress_label.config(text=f'{base} (ждём ответ{dots})')
            self.root.after(500,self._progress_heartbeat)
    def stop(self):
        if self.scan_running:
            log('SCAN STOP requested')
            self.stop_event.set(); self.status.config(text='Останавливаю сканирование…'); self.stop_btn.config(state='disabled')
    def clear(self):
        for i in self.tree.get_children():self.tree.delete(i)
        self.all_results=[]; self._order_counter=0; self._update_stats([],[])

    def scan(self):
        try:
            reset_tme_probe_cache()  # свежая проверка доступности t.me на каждое новое сканирование (см. комментарий у tme_reachable)
            log(f'SCAN begin dynamic={self.scan_dynamic_sources} settings={self.scan_settings}')
            concurrency=int(self.scan_settings.get('concurrency',64) or 64)
            global NET_GATE; NET_GATE=threading.Semaphore(max(1,concurrency))  # один общий лимит на все сетевые проверки этого скана (см. комментарий у NET_GATE)
            dynamic_target=int(self.scan_settings.get('dynamic_target',40) or 40)
            enhanced=bool(self.scan_enhanced_search)
            # v30 (пункт №1 обращения): вместо одной галочки «другие виды прокси» — выбор
            # по видам (MTProto/SOCKS5/HTTP/WEB). Ищутся, разбираются, проверяются и
            # показываются ТОЛЬКО выбранные виды; у каждого свои готовые списки и свой
            # динамический поиск (см. TYPED_STATIC_SOURCES, discover_sources(types=...)).
            types=normalize_types(enabled_types_from_settings(self.scan_settings)) or ('mtproto',)
            include_other=any(t!='mtproto' for t in types)  # есть ли вообще не-MTProto виды
            log(f'SCAN types={",".join(types)}')
            github_token=(self.scan_settings.get('github_token') or '').strip() or None
            # Пункт №1 обращения v29: "подключение к telegram можно осуществлять через
            # рабочий прокси... касается всех telegram источников" — парсим ОДИН раз в
            # начале сканирования (не на каждый t.me-запрос) и используем везде, где
            # программа читает t.me (см. tme_reachable/fetch_telegram_channel_text).
            telegram_proxy_text=(self.scan_settings.get('telegram_proxy') or '').strip()
            # v30: в этом же поле можно задать не прокси, а шаблон СВОЕГО шлюза чтения
            # (URL с {url}/{urlenc}/{ch}) — см. parse_gateway_template.
            tg_gateway=parse_gateway_template(telegram_proxy_text)
            telegram_proxy=parse_single_proxy_input(telegram_proxy_text) if (telegram_proxy_text and not tg_gateway) else None
            if tg_gateway:
                log(f'TG-GATEWAY: используется свой шлюз {tg_gateway[:100]}')
            elif telegram_proxy_text and not telegram_proxy:
                log(f'TG-PROXY: не удалось распознать формат «{telegram_proxy_text[:80]}» — прокси для t.me не используется')
                self.q.put(('status','Рабочий прокси для Telegram-источников не распознан — работаем без него (см. лог).'))
            elif telegram_proxy and telegram_proxy.get('ptype') not in ('socks5','http'):
                log(f'TG-PROXY: указан {telegram_proxy.get("ptype")}-прокси {telegram_proxy["server"]}:{telegram_proxy["port"]} — такой тип технически не может пересылать произвольный HTTPS-трафик (только SOCKS5/HTTP могут), продолжаем без прокси для t.me')
                self.q.put(('status',f'Указан {telegram_proxy.get("ptype")}-прокси — он не подходит для чтения t.me (нужен SOCKS5/HTTP), работаем без него.'))
                telegram_proxy=None
            elif telegram_proxy:
                log(f'TG-PROXY: используется {telegram_proxy["ptype"]}-прокси {telegram_proxy["server"]}:{telegram_proxy["port"]} для чтения t.me-источников')
            # v30 (пункт №2): шаблон своего шлюза в том же поле + галочка публичных шлюзов;
            # настраиваем маршруты чтения t.me и проверяем их ОДИН раз в начале.
            configure_tg_access(proxy=telegram_proxy,gateway=tg_gateway,use_gateways=bool(self.scan_settings.get('tg_gateways',True)))
            if enhanced or not self.scan_dynamic_sources:  # тг-каналы читаются только в этих режимах
                self.q.put(('status','Проверяю доступ к Telegram-каналам (прямой, через зеркала и шлюзы)…'))
                tme_reachable(proxy=telegram_proxy)
                tg_note=describe_tg_access()
                if tg_note:
                    log('TG-ACCESS '+tg_note); self.q.put(('status',tg_note))
            used_source_urls=set()  # сырые URL уже опробованных источников — чтобы "дозапрос" не тратил время на повтор тех же находок
            if self.scan_dynamic_sources:
                # Требование: при включённом динамическом поиске встроенный список НЕ
                # используется вообще — берутся только источники, которые программа
                # реально найдёт сама.
                discovery_time=float(self.scan_settings.get('discovery_time',25) or 25)
                self.q.put(('status',f'{"Улучшенный" if enhanced else "Динамический"} поиск источников (цель: {dynamic_target}, до {discovery_time:.0f} с)…'))
                discovered=discover_sources(self.stop_event,lambda s:self.q.put(('status',s)),target=dynamic_target,enhanced=enhanced,time_budget=discovery_time,github_token=github_token,telegram_proxy=telegram_proxy,types=types)
                used_source_urls.update(url for url,_ in discovered)
                sources=[(name,url) for url,name in discovered]
                log(f'DYNAMIC-ONLY sources discovered={len(sources)} enhanced={enhanced} (встроенный список не используется)')
                self.q.put(('status',f'Источников найдено {("улучшенным" if enhanced else "динамическим")} поиском: {len(sources)}…'))
                if not sources and not typed_sources_for(types) and not self.stop_event.is_set():
                    raise RuntimeError('Не удалось найти источники динамически за отведённое время. Если это повторилось сразу после предыдущего сканирования — вероятно, временно исчерпан лимит запросов к GitHub API (он общий у всех, без входа в аккаунт, и сбрасывается примерно через минуту): подождите и повторите. Либо попробуйте увеличить «Время поиска» или «Источников (авто)», включить «Улучшенный поиск», либо отключить динамический поиск, чтобы использовать встроенный список.')
            else:
                # MTProto-списки берём только если MTProto выбран; тг-каналы из встроенного
                # списка читаются при любом выборе (из текста постов разбираются выбранные виды).
                sources=[x for x in STATIC_SOURCES if ('mtproto' in types or x[1].startswith('tgchannel://'))]
                self.q.put(('status',f'Использую {len(sources)} встроенных источников…'))
                log(f'STATIC sources count={len(sources)}')
            extra_typed=typed_sources_for(types)
            if extra_typed:
                sources=sources+extra_typed
                log(f'TYPED sources added={len(extra_typed)} types={",".join(types)}')
            if 'web' in types and not self.scan_dynamic_sources and not enhanced:
                self.q.put(('status','WEB-прокси: готовых публичных списков нет — ищу ссылки tg://webproxy в тг-каналах и найденных источниках (удобнее с динамическим/улучшенным поиском).'))
            if self.stop_event.is_set():
                log('SCAN stopped before source loading'); return

            candidates={}; source_errors=[]; total_sources_loaded=0

            def load_sources(src_list):
                """Fetch+parse a batch of sources into `candidates` (deduped by
                server/port/secret). Returns how many genuinely NEW proxy candidates this
                batch contributed, so callers (incl. the top-up loop below) know whether
                it was worth it."""
                nonlocal total_sources_loaded
                if not src_list: return 0
                before=len(candidates)
                loaded=0
                source_workers=max(1,min(16,concurrency,len(src_list)))
                self.q.put(('progress_indeterminate',f'Загрузка источников: 0 / {len(src_list)}'))
                with ThreadPoolExecutor(max_workers=source_workers) as ex:
                    fs={}
                    for name,url in src_list:
                        ptype=OTHER_SOURCE_TYPES.get(url) or _SOURCE_TYPE_HINTS.get(url)  # 'socks5'/'http' для «голых» списков одного вида, иначе None
                        if ptype and ptype not in types: continue  # вид не выбран пользователем
                        if url.startswith('tgchannel://'):
                            fs[ex.submit(_load_channel_source,url,include_other,telegram_proxy)]=(url,name,None)
                        elif ptype:
                            fs[ex.submit(http_get,url,8)]=(url,name,ptype)
                        else:
                            fs[ex.submit(http_get,url,8)]=(url,name,None)
                    log(f'SOURCE LOAD submitted={len(fs)} workers={source_workers}')
                    for f in as_completed(fs):
                        url,name,ptype=fs[f]; loaded+=1; total_sources_loaded+=1
                        if self.stop_event.is_set():
                            log('SCAN stop during source loading'); break
                        try:
                            text=f.result()
                            ps=parse_typed_links(text,ptype) if ptype else parse_proxies(text,types=types)
                            for p in ps:
                                p['source']=name
                                candidates[_pkey(p)]=p
                            log(f'SOURCE OK {name} url={url} bytes={len(text.encode("utf-8"))} parsed={len(ps)} total={len(candidates)}')
                            self.q.put(('progress_source',(loaded,len(src_list)))); self.q.put(('status',f'Источник {loaded}/{len(src_list)}: {name} • +{len(ps)} • всего {len(candidates)}'))
                        except Exception as e:
                            err=f'{type(e).__name__}: {e}'; source_errors.append(f'{name}: {err}')
                            log(f'SOURCE FAIL {name} url={url} error={err}', True)
                            self.q.put(('progress_source',(loaded,len(src_list)))); self.q.put(('status',f'Источник {loaded}/{len(src_list)} недоступен: {name} • {str(e)[:120]}'))
                return len(candidates)-before

            # ВАЖНО: никогда не прекращаем загрузку источников только потому, что уже набрали N кандидатов.
            # Иначе нужное число рабочих прокси может не набраться после TCP/geo/фильтров.
            load_sources(sources)
            log(f'SOURCE LOAD finished loaded={total_sources_loaded}/{len(sources)} candidates={len(candidates)} errors={len(source_errors)}')
            if not candidates:
                detail='; '.join(source_errors[:12]) if source_errors else 'Источники не вернули данных.'
                raise RuntimeError('Не удалось загрузить ни одного прокси-кандидата. См. TelegramProxyScanner_debug.log. Детали: '+detail)

            target=self.scan_settings['limit']; max_ping=self.scan_settings['max_ping']
            wanted_country=self.scan_settings['country']; wanted_provider=self.scan_settings['provider']
            stability_on=self.scan_settings['stability']; stability_seconds=self.scan_settings['stability_seconds']
            found=[]; checked=0; found_lock=threading.Lock(); target_reached=threading.Event()
            already_checked_keys=set()  # не проверяем повторно один и тот же прокси в раундах дозапроса

            def passes_filters(p):
                country=country_name(p); provider=provider_name(p)
                country_ok=(wanted_country=='Все страны' or country==wanted_country)
                provider_ok=(wanted_provider=='Все провайдеры' or wanted_provider==provider or (wanted_provider and wanted_provider in provider))
                return country_ok and provider_ok

            def accept(p):
                with found_lock:
                    if target_reached.is_set() or len(found)>=target: return
                    found.append(p); found.sort(key=lambda x:x.get('ping',999999))
                    self.q.put(('partial',list(found)))
                    if len(found)>=target:
                        log(f'TARGET REACHED target={target} checked={checked}')
                        target_reached.set()

            def stability_job(p):
                # Runs the full multi-second stability test on a background worker; the
                # proxy is only ever shown to the user (accept()) if it passes, which is
                # what satisfies "проверка перед тем как отдать пользователю в список".
                if target_reached.is_set() or self.stop_event.is_set(): return
                passed,detail=stability_test(p,stability_seconds,self.stop_event,target_reached,max_ping=max_ping)
                if passed:
                    p['stability']='Онлайн - Проверен'
                    accept(p)
                else:
                    log(f'PROXY DROPPED (стабильность) {p["server"]}:{p["port"]}: {detail}')

            def run_check_round(proxy_list):
                """Run the online/ping/filter/stability pipeline over one batch of
                proxies, feeding passers into the shared `found` list. Used both for the
                initial candidate batch and for each top-up batch, so results from every
                round accumulate into the same `found`/`checked` counters."""
                nonlocal checked
                if not proxy_list or self.stop_event.is_set() or target_reached.is_set(): return
                log(f'CHECK round start proxies={len(proxy_list)} target={target} max_ping={max_ping} country={wanted_country} provider={wanted_provider} stability={stability_on} stability_seconds={stability_seconds}')
                phase2_ex=ThreadPoolExecutor(max_workers=max(2,concurrency//4)) if stability_on else None
                try:
                    with ThreadPoolExecutor(max_workers=concurrency) as ex:
                        pending={ex.submit(check_proxy_online,p,2.6):p for p in proxy_list}
                        for f in as_completed(pending):
                            if self.stop_event.is_set() or target_reached.is_set(): break
                            p=pending[f]
                            try: ok,ms,ip,err,method=f.result()
                            except Exception as e: ok,ms,ip,err,method=False,None,None,str(e),'error'; log(f'CHECK worker exception: {e}', True)
                            checked+=1; self.q.put(('progress',checked))
                            p.update(ok=ok,ping=ms,ip=ip,error=err,check_method=method)
                            if not (ok and ms is not None and ms<=max_ping): continue
                            p['geo']=geo(ip)
                            log(f'PROXY ONLINE {p["server"]}:{p["port"]} ping={ms} method={method} country={country_name(p)} provider={provider_name(p)}')
                            if not passes_filters(p): continue
                            if method=='tcp-only':
                                p['stability']='Онлайн (не проверено)'
                            elif method=='web':
                                p['stability']='Онлайн (HTTPS проверен)'
                            else:
                                p['stability']='Онлайн'
                            if stability_on and method in STABILITY_SUPPORTED_METHODS:
                                phase2_ex.submit(stability_job,p)
                            else:
                                accept(p)
                        for pf in pending:
                            if not pf.done(): pf.cancel()
                finally:
                    if phase2_ex: phase2_ex.shutdown(wait=True,cancel_futures=True)

            # Порядок проверки: сначала виды с высокой долей рабочих (MTProto, WEB), затем
            # SOCKS5/HTTP из больших универсальных списков — иначе тысячи «голых» адресов
            # заняли бы все потоки раньше, чем дойдёт очередь до MTProto.
            _rank={t:i for i,t in enumerate(('mtproto','web','socks5','http'))}
            proxies=sorted(candidates.values(),key=lambda p:_rank.get(p.get('ptype','mtproto'),9)); self.q.put(('progress_check_start',len(proxies)))
            already_checked_keys.update(candidates.keys())
            run_check_round(proxies)

            # ---- Дозапрос (top-up), пункт №2 из обращения пользователя ----
            # Идея пользователя: если рабочих прокси набралось меньше, чем запрошено,
            # искать ещё источники и продолжать поиск, вместо того чтобы просто
            # останавливаться на том, что нашлось с первого раза. Решение принято, но не
            # "как есть" — число раундов настраивается пользователем ("Попыток дозапроса").
            # ИСПРАВЛЕНО (баг из обращения: "поставил 5, выполнилось только 2"): раньше
            # суммарное время на ВСЕ раунды было жёстко зашито в 60 секунд независимо от
            # того, сколько раундов попросил пользователь — при 5 раундах время молча
            # заканчивалось после 2-3. Теперь общий потолок считается ОТ запрошенного числа
            # раундов и выбранного пользователем «Время поиска» (а не от отдельной короткой
            # константы) — так что все заказанные раунды успевают отработать. Внешний предел
            # всё равно есть (не превращается в "часы ожидания"), но он считается от самих
            # настроек пользователя, а не от скрытого фиксированного числа, которое их
            # перекрывало.
            max_topup_rounds=int(self.scan_settings.get('topup_rounds',MAX_TOPUP_ROUNDS) or 0)
            discovery_time=float(self.scan_settings.get('discovery_time',25) or 25)
            per_round_budget=max(TOPUP_DISCOVERY_TIME_BUDGET,discovery_time)
            # +90с на раунд сверху — запас на сам цикл проверки найденных прокси между
            # раундами поиска источников (он тоже занимает время, не только поиск источников).
            topup_round=0; topup_deadline=time.time()+max_topup_rounds*(per_round_budget+90.0)
            while (self.scan_dynamic_sources and not self.stop_event.is_set() and not target_reached.is_set()
                   and len(found)<target and topup_round<max_topup_rounds and time.time()<topup_deadline):
                topup_round+=1
                remaining_budget=max(5.0,min(per_round_budget,topup_deadline-time.time()))
                self.q.put(('status',f'Прокси набралось меньше, чем нужно ({len(found)}/{target}) — доп. поиск источников, раунд {topup_round}/{max_topup_rounds}…'))
                log(f'TOPUP round={topup_round} found={len(found)}/{target} budget={remaining_budget:.1f}s')
                more=discover_sources(self.stop_event,lambda s:self.q.put(('status',s)),target=dynamic_target,
                                       enhanced=enhanced,exclude=used_source_urls,time_budget=remaining_budget,github_token=github_token,telegram_proxy=telegram_proxy,types=types)
                if not more or self.stop_event.is_set():
                    log(f'TOPUP round={topup_round} no new sources found — остановка дозапроса'); break
                used_source_urls.update(url for url,_ in more)
                added=load_sources([(name,url) for url,name in more])
                log(f'TOPUP round={topup_round} new_sources={len(more)} new_candidates={added} total_candidates={len(candidates)}')
                if added<=0:
                    log(f'TOPUP round={topup_round} новые источники не дали новых кандидатов — остановка дозапроса'); break
                new_proxies=sorted([p for k,p in candidates.items() if k not in already_checked_keys],key=lambda p:_rank.get(p.get('ptype','mtproto'),9))
                already_checked_keys.update(k for k,_ in candidates.items())
                self.q.put(('progress_extend',checked+len(new_proxies)))
                run_check_round(new_proxies)

            found.sort(key=lambda p:p.get('ping',999999))
            log(f'SCAN complete checked={checked} found={len(found)} target={target} topup_rounds={topup_round}')
            self.q.put(('results',found)); self.q.put(('progress_finished',None))
            if self.stop_event.is_set():
                self.q.put(('status',f'Остановлено • найдено {len(found)} из {target}'))
            elif len(found)<target:
                self.q.put(('status',f'Готово • найдено {len(found)} из {target} — проверены все доступные кандидаты'))
            else:
                self.q.put(('status',f'Готово • найдено {target} прокси'))
        except Exception as e:
            log(f'SCAN FATAL {type(e).__name__}: {e}', True)
            self.q.put(('progress_error',str(e))); self.q.put(('error',str(e)))
        finally:
            self.q.put(('enable',None))

    def accept_filter(self,p):
        if self.settings['country']!='Все страны' and country_name(p)!=self.settings['country']: return False
        if self.settings['provider']!='Все провайдеры' and self.settings['provider'] not in provider_name(p): return False
        if self.settings['only_ok'] and not p.get('ok'): return False
        return True
    def filtered_sorted(self):
        x=[p for p in self.all_results if self.accept_filter(p)]
        if self.lock_order.get(): x.sort(key=lambda p:p.get('_position',10**9))
        else: x.sort(key=lambda p:(not bool(p.get('ok')), p.get('ping') if p.get('ping') is not None else 999999))
        return x
    def apply_filters(self): self.sync_settings(); self.render(self.all_results)
    def render(self,results):
        self.all_results=results
        for p in self.all_results:
            if '_position' not in p:
                p['_position']=self._order_counter; self._order_counter+=1
        countries=sorted({country_name(p) for p in results if country_name(p)!='Неизвестно'}); providers=sorted({provider_name(p) for p in results if provider_name(p)})
        self.country_cb['values']=['Все страны']+countries; self.provider_cb['values']=['Все провайдеры']+providers
        if self.country.get() not in self.country_cb['values']: self.country.set('Все страны'); self.settings['country']='Все страны'
        if self.provider.get() not in self.provider_cb['values']: self.provider.set('Все провайдеры'); self.settings['provider']='Все провайдеры'
        for i in self.tree.get_children(): self.tree.delete(i)
        visible=self.filtered_sorted()
        for idx,p in enumerate(visible):
            g=p.get('geo') or {}; provider=g.get('isp') or g.get('org') or g.get('as') or '—'; ping=p.get('ping')
            if p.get('stability')=='Онлайн - Проверен': status='●  Онлайн - Проверен'
            elif p.get('check_method')=='tcp-only': status='●  Онлайн (не проверено)'
            elif p.get('check_method')=='web': status='●  Онлайн (HTTPS проверен)'
            elif p.get('ok'): status='●  Онлайн'
            else: status='●  Offline'
            if not p.get('ok'): tag='bad'
            elif ping is not None and ping<=100: tag='good'
            else: tag='slow'
            iid=str(idx)
            ptype_label=PTYPE_LABELS.get(p.get('ptype','mtproto'),'MTProto')
            self.tree.insert('','end',iid=iid,values=(ptype_label,country_name(p),provider,p['server'],p['port'],f'{ping:.1f} ms' if ping is not None else '—',p.get('source','—'),status,''),tags=(tag,))
        self._update_stats(results,visible)
    def _update_stats(self,all_results,visible):
        online=[p for p in all_results if p.get('ok')]; ps=[p.get('ping') for p in online if p.get('ping') is not None]
        self.stat_found.config(text=str(len(all_results))); self.stat_online.config(text=str(len(online))); self.stat_visible.config(text=str(len(visible))); self.stat_ping.config(text=f'{sum(ps)/len(ps):.0f} ms' if ps else '—'); self.count_label.config(text=f'{len(visible)} / {self.settings["limit"]}')
    def render_current(self):
        self.render(self.all_results)


    def row_action(self,event):
        item=self.tree.identify_row(event.y)
        if item:self.open_proxy(item)
    def row_click(self,event):
        # Single click selects the proxy. Double-click opens it in Telegram.
        return None
    def _proxy_for_item(self,item):
        visible=self.filtered_sorted(); i=int(item); return visible[i] if 0<=i<len(visible) else None
    def open_proxy(self,item):
        try:
            p=self._proxy_for_item(item)
            if not p: return
            self.open_proxy_data(p)
        except Exception as e: messagebox.showerror(APP_TITLE,str(e))
    def open_proxy_data(self,p):
        ptype=p.get('ptype','mtproto')
        # ИСПРАВЛЕНО по следующему обращению пользователя: он нашёл и прислал реальную
        # рабочую ссылку подключения WEB-прокси в Telegram Desktop
        # ("tg://webproxy?server=...&secret=..."), подтверждённую при исследовании
        # (см. parse_webproxy_link/_check_web_proxy) — WEB раньше ошибочно считался
        # "без способа подключения", как HTTP; это было неверно. Теперь WEB подключается
        # в один клик точно так же, как MTProto/SOCKS5. По-настоящему без готовой ссылки
        # в Telegram Desktop остался только HTTP.
        if ptype=='http':
            # У HTTP прокси нет возможности подключения в один клик — у Telegram Desktop
            # просто не существует протокола-ссылки для него (только tg://proxy для
            # MTProto, tg://socks для SOCKS5 и tg://webproxy для WEB). Честно показываем
            # это и даём данные для ручной настройки вместо того, чтобы делать вид, что
            # подключение сработало.
            hostport=f"{p['server']}:{p['port']}"
            try:
                self.root.clipboard_clear(); self.root.clipboard_append(hostport)
                copied='\n\nАдрес скопирован в буфер обмена.'
            except Exception:
                copied=''
            messagebox.showinfo(APP_TITLE,f'Для прокси типа HTTP в Telegram Desktop нет готовой ссылки для подключения в один клик (такой возможности не существует — это ограничение самого Telegram, не программы).\n\nАдрес: {hostport}\nНастройте его вручную как HTTP-прокси в системе или нужном приложении.{copied}')
            return
        if not tg_installed():
            messagebox.showwarning(APP_TITLE,'Telegram Desktop не зарегистрировал протокол tg://. Установите Telegram Desktop и повторите попытку.'); return
        if not add_to_telegram(p['link']): raise RuntimeError('Windows не передал tg:// Telegram Desktop')
        self.status.config(text='Прокси передан Telegram Desktop — подтвердите добавление в Telegram, если появится окно')
    def ping_loop(self):
        # Note: the stability check itself now runs once, during the scan, on every
        # candidate BEFORE it is ever added to the visible list (see stability_test /
        # scan()). This loop only does the lightweight periodic re-ping of proxies
        # already accepted into the list, so users can see if a listed proxy later goes
        # offline; it no longer re-runs (or can crash) the stability logic per row, which
        # used to incorrectly flip FakeTLS proxies to "offline" every cycle.
        while True:
            started=time.perf_counter(); interval=self.settings.get('interval',1.0)
            if self.all_results and not self.scan_running and self.settings.get('auto_ping'):
                targets=list(self.all_results)
                def one(p):
                    ok,ms,ip,err=tcp_probe(p,min(2.0,max(.35,interval))); p.update(ok=ok,ping=ms,ip=ip,error=err)
                try:
                    workers=max(1,min(30,self.settings.get('concurrency',64),len(targets)))
                    with ThreadPoolExecutor(max_workers=workers) as ex: list(ex.map(one,targets))
                except Exception as e: log(f'AUTO PING FAIL: {e}',True)
                self.q.put(('refresh',None))
            time.sleep(max(.1,interval-(time.perf_counter()-started)))

    def open_log(self):
        try:
            log(f'LOG OPEN requested path={LOG_FILE}')
            if sys.platform=='win32':
                os.startfile(LOG_FILE)
            else:
                subprocess.Popen(['xdg-open',LOG_FILE])
        except Exception as e:
            messagebox.showinfo(APP_TITLE, f'Файл лога:\n{LOG_FILE}\n\nНе удалось открыть автоматически: {e}')

    def export(self):
        self.sync_settings(); visible=self.filtered_sorted()
        if not visible:messagebox.showinfo(APP_TITLE,'Нет прокси, соответствующих текущим фильтрам.');return
        path=filedialog.asksaveasfilename(defaultextension='.txt',filetypes=[('Text','*.txt'),('JSON','*.json')])
        if not path:return
        if path.lower().endswith('.json'):
            with open(path,'w',encoding='utf-8') as f:json.dump(visible,f,ensure_ascii=False,indent=2)
        else:
            with open(path,'w',encoding='utf-8') as f:f.write('\n'.join(p['link'] for p in visible))
        self.status.config(text='Экспортировано')

    def poll(self):
        try:
            while True:
                typ,val=self.q.get_nowait()
                if typ.startswith('progress'):
                    self._progress_last_tick=time.time()  # см. _progress_heartbeat
                if typ=='status':
                    self.status.config(text=val)
                elif typ=='progress_indeterminate':
                    self.progress.stop(); self.progress.config(mode='indeterminate'); self.progress.start(12); self.progress_label.config(text=val)
                elif typ=='progress_source':
                    done,total=val; self.progress.stop(); self.progress.config(mode='determinate',maximum=max(1,total),value=done); self.progress_label.config(text=f'Источники: {done}/{total}')
                elif typ=='progress_check_start':
                    self.progress.stop(); self.progress.config(mode='determinate',maximum=max(1,val),value=0); self.progress_label.config(text=f'Проверка: 0/{val}')
                elif typ=='progress_extend':
                    # Используется при "дозапросе" прокси вместо progress_check_start: та же
                    # полоса продолжает расти с текущего значения (которое уже равно старому
                    # максимуму), а не визуально обрушивается до 0%, пока новые источники
                    # загружаются — раньше это выглядело как "зависание, а потом рывок".
                    self.progress.stop(); self.progress.config(mode='determinate',maximum=max(1,val))
                elif typ=='progress':
                    self.progress['value']=val; self.progress_label.config(text=f'Проверка: {val}/{int(float(self.progress["maximum"]))}')
                elif typ=='progress_done':
                    self.progress.stop(); self.progress.config(mode='determinate'); self.progress['value']=self.progress['maximum']; self.progress_label.config(text='100%')
                elif typ=='progress_finished':
                    # По завершении сканирования показываем текст вместо заполненной полосы —
                    # полностью залитый прогресс-бар выглядит так, будто что-то зависло.
                    self.progress.stop(); self.progress.config(mode='determinate'); self.progress['value']=0; self.progress_label.config(text='Сканирование завершено')
                elif typ=='progress_error':
                    self.progress.stop(); self.progress.config(mode='determinate'); self.progress['value']=0; self.progress_label.config(text='Ошибка')
                elif typ in ('results','partial'):
                    self.render(val)
                elif typ=='refresh':
                    self.render(self.all_results)
                    if not self.scan_running: self.status.config(text=f'Автопроверка • {time.strftime("%H:%M:%S")}')
                elif typ=='error':
                    self.status.config(text=f'Сканирование завершено: ошибка — {val}')
                    messagebox.showerror(APP_TITLE,val)
                elif typ=='enable':
                    self.scan_running=False; self.scan_btn.config(state='normal'); self.stop_btn.config(state='disabled'); self.export_btn.config(state='normal')
        except queue.Empty:
            pass
        self.root.after(80,self.poll)

if __name__=='__main__':
    root=tk.Tk()
    try:root.call('tk','scaling',1.0)
    except:pass
    App(root);root.mainloop()
