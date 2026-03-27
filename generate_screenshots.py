"""Generate realistic dashboard screenshots for the vitrine - each unique"""
from PIL import Image, ImageDraw, ImageFont
import os, math, random

random.seed(2026)

BG = (10, 10, 18)
BG2 = (17, 17, 26)
BG3 = (22, 22, 34)
CARD = (20, 22, 35)
BORDER = (35, 38, 55)
TEXT = (220, 220, 240)
TEXT2 = (120, 120, 150)
TEXT3 = (80, 80, 100)
BLUE = (77, 159, 255)
PURPLE = (180, 125, 255)
GREEN = (61, 255, 180)
RED = (255, 77, 106)
AMBER = (255, 179, 71)

W, H = 1280, 720
os.makedirs('screenshots', exist_ok=True)

try:
    F_TITLE = ImageFont.truetype('C:/Windows/Fonts/arialbd.ttf', 20)
    F_BIG = ImageFont.truetype('C:/Windows/Fonts/consolab.ttf', 36)
    F_MED = ImageFont.truetype('C:/Windows/Fonts/arialbd.ttf', 14)
    F_SM = ImageFont.truetype('C:/Windows/Fonts/arial.ttf', 12)
    F_XS = ImageFont.truetype('C:/Windows/Fonts/arial.ttf', 10)
    F_HUGE = ImageFont.truetype('C:/Windows/Fonts/consolab.ttf', 48)
except:
    F_TITLE = F_BIG = F_MED = F_SM = F_XS = F_HUGE = ImageFont.load_default()

def new_img():
    img = Image.new('RGB', (W, H), BG)
    return img, ImageDraw.Draw(img)

def draw_topbar(draw, title, subtitle, accent=BLUE):
    draw.rectangle([0, 0, W, 48], fill=BG2)
    draw.rectangle([0, 48, W, 50], fill=(*accent, 180))
    # Window dots
    for i, c in enumerate([(255,95,87),(255,189,46),(39,201,63)]):
        draw.ellipse([14+i*20, 16, 28+i*20, 30], fill=c)
    draw.text((90, 12), title, fill=TEXT, font=F_TITLE)
    draw.text((90, 33), subtitle, fill=TEXT2, font=F_XS)
    # Status badge
    draw.rounded_rectangle([W-160, 12, W-14, 38], radius=5, fill=(16,80,40))
    draw.text((W-148, 16), "EN DIRECT", fill=GREEN, font=F_SM)

def draw_sidebar(draw, items, active=0, accent=BLUE):
    draw.rectangle([0, 50, 180, H], fill=BG2)
    draw.rectangle([180, 50, 181, H], fill=BORDER)
    for i, (icon, label) in enumerate(items[:14]):
        y = 60 + i * 38
        if i == active:
            draw.rounded_rectangle([6, y, 174, y+32], radius=6, fill=(*accent[:3], 40))
            draw.rectangle([0, y+4, 3, y+28], fill=accent)
            color = accent
        else:
            color = TEXT2
        draw.text((18, y+8), icon, fill=color, font=F_SM)
        draw.text((38, y+8), label, fill=color, font=F_SM)

def draw_card(draw, x, y, w, h, title=None):
    draw.rounded_rectangle([x, y, x+w, y+h], radius=10, fill=CARD, outline=BORDER)
    if title:
        draw.text((x+14, y+10), title, fill=TEXT2, font=F_MED)

def draw_metric(draw, x, y, w, val, label, color):
    draw_card(draw, x, y, w, 80)
    draw.text((x+14, y+14), val, fill=color, font=F_BIG)
    draw.text((x+14, y+56), label, fill=TEXT3, font=F_XS)

def draw_line_chart(draw, x, y, w, h, color, data=None, second=None):
    if not data:
        data = [random.gauss(0.5, 0.15) for _ in range(50)]
    data = [max(0.05, min(0.95, d)) for d in data]
    pts = [(x + 10 + i*(w-20)/len(data), y + h - 20 - d*(h-40)) for i, d in enumerate(data)]
    for i in range(len(pts)-1):
        draw.line([pts[i], pts[i+1]], fill=color, width=2)
    # Fill under
    for i in range(len(pts)-1):
        x1, y1 = pts[i]; x2, y2 = pts[i+1]
        for row in range(int(min(y1,y2)), y+h-20):
            alpha = max(0, 30 - (row - int(min(y1,y2))) // 3)
            if alpha > 0:
                draw.line([(x1, row), (x2, row)], fill=(*color, alpha))
    if second:
        pts2 = [(x + 10 + i*(w-20)/len(second), y + h - 20 - d*(h-40)) for i, d in enumerate(second)]
        for i in range(len(pts2)-1):
            draw.line([pts2[i], pts2[i+1]], fill=GREEN, width=1)

def draw_bar_chart(draw, x, y, w, h, colors=None, horiz=False, labels=None, data=None):
    if not data:
        data = [random.randint(20, 95) for _ in range(6)]
    if not colors:
        colors = [BLUE, PURPLE, GREEN, AMBER, RED, BLUE]
    if horiz:
        bh = min(22, (h - 30) // len(data))
        for i, v in enumerate(data):
            by = y + 30 + i * (bh + 6)
            bw = int((v / 100) * (w - 80))
            c = colors[i % len(colors)]
            draw.rounded_rectangle([x+60, by, x+60+bw, by+bh], radius=4, fill=c)
            if labels and i < len(labels):
                draw.text((x+8, by+4), labels[i], fill=TEXT2, font=F_XS)
    else:
        bw = min(30, (w - 20) // len(data))
        gap = (w - 20 - bw * len(data)) // max(len(data), 1)
        for i, v in enumerate(data):
            bx = x + 10 + i * (bw + gap)
            bh_val = int((v / 100) * (h - 50))
            by = y + h - 10 - bh_val
            c = colors[i % len(colors)]
            draw.rounded_rectangle([bx, by, bx+bw, y+h-10], radius=3, fill=c)

def draw_donut(draw, cx, cy, r, data, colors):
    start = -90
    for i, v in enumerate(data):
        angle = v * 3.6
        for a in range(int(start), int(start + angle)):
            rad = math.radians(a)
            for dr in range(int(r*0.6), r):
                px = cx + dr * math.cos(rad)
                py = cy + dr * math.sin(rad)
                if 0 <= px < W and 0 <= py < H:
                    draw.point((int(px), int(py)), fill=colors[i % len(colors)])
        start += angle

def draw_table(draw, x, y, w, h, headers, rows, colors=None):
    rh = min(24, (h - 30) // max(len(rows)+1, 1))
    # Header
    for j, hdr in enumerate(headers):
        draw.text((x + 10 + j * (w // len(headers)), y + 8), hdr, fill=TEXT2, font=F_XS)
    draw.line([(x+5, y+26), (x+w-5, y+26)], fill=BORDER)
    # Rows
    for i, row in enumerate(rows[:8]):
        ry = y + 32 + i * rh
        for j, cell in enumerate(row):
            c = TEXT if j == 0 else (colors[i] if colors and i < len(colors) else TEXT2)
            draw.text((x + 10 + j * (w // len(headers)), ry), str(cell), fill=c, font=F_XS)


# ═══════════════════════════════════════════════════════════════
# 1. NETGUARD DASHBOARD
# ═══════════════════════════════════════════════════════════════
img, d = new_img()
draw_topbar(d, 'NetGuard Pro', 'Dashboard temps reel — Surveillance reseau')
sidebar = [('📊','Tableau de bord'),('📦','Paquets live'),('⚠','Menaces'),('🚫','IPs bloquees'),
           ('🔥','Regles pare-feu'),('📝','Rapports'),('⚙','Configuration'),('🌍','Carte mondiale'),
           ('🖥','Reseau LAN'),('📡','Service Manager'),('📋','Log audit'),('👤','Utilisateurs')]
draw_sidebar(d, sidebar, 0)

# Metrics
mx = 195
draw_metric(d, mx, 60, 240, '12,847', 'Paquets / sec', BLUE)
draw_metric(d, mx+255, 60, 240, '342', 'Bloques  —  2.7%', RED)
draw_metric(d, mx+510, 60, 240, '18', 'Menaces  0 critiques', AMBER)
draw_metric(d, mx+765, 60, 240, '847', 'Connexions actives', GREEN)

# Traffic chart
draw_card(d, mx, 155, 530, 200, 'TRAFIC RESEAU (60s)')
traffic_in = [0.3+0.2*math.sin(i*0.15)+random.gauss(0,0.05) for i in range(50)]
traffic_out = [0.25+0.15*math.sin(i*0.12+1)+random.gauss(0,0.04) for i in range(50)]
draw_line_chart(d, mx, 155, 530, 200, BLUE, traffic_in, traffic_out)
d.text((mx+14, 335), '— Entrant  ', fill=BLUE, font=F_XS)
d.text((mx+100, 335), '— Sortant  ', fill=GREEN, font=F_XS)
d.text((mx+180, 335), '— Bloque', fill=RED, font=F_XS)

# Perf chart
draw_card(d, mx+545, 155, 285, 200, 'PERFORMANCE')
draw_bar_chart(d, mx+545, 175, 285, 170, [BLUE,PURPLE,BLUE,PURPLE,GREEN,BLUE,PURPLE,GREEN],
               data=[78,92,45,88,65,82,95,70])

# Geo pie
draw_card(d, mx+845, 155, 200, 200, 'PAYS ATTAQUANTS')
draw_donut(d, mx+945, 280, 55, [30,22,18,15,15], [RED, AMBER, BLUE, PURPLE, GREEN])
for i, (c, cc) in enumerate([('CN 30%',RED),('RU 22%',AMBER),('US 18%',BLUE),('BR 15%',PURPLE),('DE 15%',GREEN)]):
    d.text((mx+855, 185+i*16), c, fill=cc, font=F_XS)

# Threats table
draw_card(d, mx, 370, 345, 200, 'TYPES D\'ATTAQUES')
draw_bar_chart(d, mx, 395, 345, 170, [RED,AMBER,RED,PURPLE,AMBER,RED], horiz=True,
    labels=['Port Scan','SQLi','XSS','Brute Force','DDoS','Log4Shell'],
    data=[85,62,48,72,55,40])

# Protocols
draw_card(d, mx+360, 370, 340, 200, 'PROTOCOLES')
draw_bar_chart(d, mx+360, 395, 340, 170, [BLUE,GREEN,PURPLE,AMBER,RED,BLUE],
    data=[90,75,60,45,35,25])
for i, p in enumerate(['TCP','UDP','HTTP','DNS','TLS','ICMP']):
    d.text((mx+375+i*52, 560), p, fill=TEXT3, font=F_XS)

# Top IPs
draw_card(d, mx+715, 370, 330, 200, 'TOP IPs SUSPECTES')
ips = [('185.220.101.5','CN',92),('91.134.22.18','RU',78),('45.33.32.156','US',65),
       ('103.224.80.1','VN',58),('5.188.86.12','DE',45),('192.168.1.105','LAN',30)]
draw_bar_chart(d, mx+715, 395, 330, 170, [RED,RED,AMBER,AMBER,BLUE,GREEN], horiz=True,
    labels=[f'{ip} ({c})' for ip,c,_ in ips], data=[v for _,_,v in ips])

# Watermark
d.text((mx, H-20), 'NetGuard Pro v3.0.0', fill=TEXT3, font=F_XS)

img.save('screenshots/netguard_dashboard.png')
print('[OK] netguard_dashboard.png')


# ═══════════════════════════════════════════════════════════════
# 2. NETGUARD MAP
# ═══════════════════════════════════════════════════════════════
img, d = new_img()
draw_topbar(d, 'NetGuard Map', 'Intelligence Reseau — Carte mondiale des menaces', RED)

# Dark world map background
draw_card(d, 0, 50, W, H-50)

# Draw simplified continents as filled polygons
def draw_continent(draw, points, color=(30,35,55)):
    if len(points) >= 3:
        draw.polygon(points, fill=color, outline=(45,50,70))

# Simplified continents (rough outlines)
# North America
draw_continent(d, [(150,150),(280,120),(350,140),(380,200),(350,300),(280,320),(200,280),(120,240),(100,180)])
# South America
draw_continent(d, [(280,340),(320,330),(360,380),(370,450),(340,550),(300,580),(260,520),(250,420),(270,360)])
# Europe
draw_continent(d, [(520,130),(600,110),(640,120),(660,160),(640,200),(580,220),(530,200),(510,160)])
# Africa
draw_continent(d, [(520,230),(580,220),(620,250),(640,320),(620,430),(560,480),(500,440),(490,350),(510,270)])
# Asia
draw_continent(d, [(660,100),(800,80),(920,120),(980,180),(960,250),(900,300),(820,280),(740,260),(680,220),(650,160)])
# Australia
draw_continent(d, [(880,400),(950,380),(1010,400),(1020,440),(980,470),(920,460),(880,430)])

# Attack points
attacks = [
    (710,145,RED,12,'Moscow'),(850,170,RED,14,'Beijing'),(650,200,RED,8,'Tehran'),
    (555,310,AMBER,7,'Lagos'),(570,155,AMBER,5,'Berlin'),(540,165,RED,7,'Paris'),
    (920,195,RED,11,'Shanghai'),(320,430,AMBER,8,'Sao Paulo'),
    (260,195,GREEN,6,'New York'),(160,210,GREEN,4,'LA'),
    (940,175,RED,9,'Tokyo'),(760,250,AMBER,9,'Mumbai'),
    (630,140,RED,6,'Kyiv'),(580,340,AMBER,5,'Nairobi'),
    (960,430,GREEN,4,'Sydney'),(545,155,RED,6,'London'),
]

# Attack lines (red to green targets)
greens = [(a[0],a[1]) for a in attacks if a[2]==GREEN]
for a in attacks:
    if a[2] == RED:
        for g in greens:
            for step in range(0, 20, 4):
                t = step / 20
                px = a[0] + (g[0]-a[0])*t
                py = a[1] + (g[1]-a[1])*t
                d.ellipse([px-1,py-1,px+1,py+1], fill=(*RED[:3], 60))

# Draw points
for x, y, color, size, label in attacks:
    d.ellipse([x-size-5,y-size-5,x+size+5,y+size+5], fill=(*color[:3], 30))
    d.ellipse([x-size,y-size,x+size,y+size], fill=(*color[:3], 150))
    d.ellipse([x-2,y-2,x+2,y+2], fill=(255,255,255,200))
    d.text((x+size+4, y-6), label, fill=TEXT2, font=F_XS)

# Legend
draw_card(d, 10, 60, 170, 150)
d.text((24, 72), 'ACTIVITE PAR PAYS', fill=TEXT2, font=F_XS)
stats = [('Connexions','1,203',BLUE),('Bloquees','342',RED),('Pays','42',AMBER),('Reseaux ASN','187',PURPLE)]
for i,(l,v,c) in enumerate(stats):
    d.rounded_rectangle([20, 95+i*28, 85, 118+i*28], radius=5, fill=(*c[:3],40))
    d.text((30, 99+i*28), v, fill=c, font=F_SM)
    d.text((90, 99+i*28), l, fill=TEXT2, font=F_XS)

# Legend bar
d.text((W//2-150, H-30), '● Mon reseau', fill=BLUE, font=F_XS)
d.text((W//2-50, H-30), '● Permis', fill=GREEN, font=F_XS)
d.text((W//2+30, H-30), '● Alerte', fill=AMBER, font=F_XS)
d.text((W//2+100, H-30), '● Bloque', fill=RED, font=F_XS)

img.save('screenshots/netguard_map.png')
print('[OK] netguard_map.png')


# ═══════════════════════════════════════════════════════════════
# 3. MAILSHIELD
# ═══════════════════════════════════════════════════════════════
img, d = new_img()
draw_topbar(d, 'MailShield Pro v2.0', 'Client email securise — Anti-phishing', BLUE)
sidebar_ms = [('📥','Boite de reception'),('📤','Envoyes'),('⚠','Spam'),('🔒','Quarantaine'),
              ('📊','Statistiques'),('⚙','Configuration'),('🔑','Vault'),('📋','Logs')]
draw_sidebar(d, sidebar_ms, 0, BLUE)

mx = 195
draw_metric(d, mx, 60, 240, '1,204', 'Emails recus', BLUE)
draw_metric(d, mx+255, 60, 240, '47', 'Spam bloques', RED)
draw_metric(d, mx+510, 60, 240, '12', 'Phishing detecte', AMBER)
draw_metric(d, mx+765, 60, 240, '99.1%', 'Taux securite', GREEN)

# Email list
draw_card(d, mx, 155, 600, 400, 'BOITE DE RECEPTION')
emails = [
    ('De: alice@company.com', 'Rapport Q4 2025 - Budget final', '14:32', GREEN, 'Sur'),
    ('De: bob@partner.fr', 'RE: Contrat de service', '13:45', GREEN, 'Sur'),
    ('De: noreply@amaz0n.xyz', 'Votre compte est suspendu!', '12:20', RED, 'Phishing'),
    ('De: support@microsoft.com', 'Mise a jour securite', '11:05', GREEN, 'Sur'),
    ('De: hr@company.com', 'Calendrier vacances 2026', '10:30', GREEN, 'Sur'),
    ('De: deals@sp4m.net', 'GAGNER 1M$ MAINTENANT', '09:15', AMBER, 'Spam'),
    ('De: cto@company.com', 'Deploy v3.0 - Go/No-Go', '08:42', GREEN, 'Sur'),
    ('De: phish@g00gle.ru', 'Verifiez votre identite', '07:30', RED, 'Phishing'),
]
for i, (sender, subject, time, color, status) in enumerate(emails):
    ey = 185 + i * 44
    if i % 2 == 0:
        d.rectangle([mx+5, ey, mx+595, ey+40], fill=BG3)
    # Status badge
    d.rounded_rectangle([mx+14, ey+10, mx+70, ey+30], radius=4, fill=(*color[:3],40))
    d.text((mx+20, ey+13), status, fill=color, font=F_XS)
    d.text((mx+80, ey+6), sender, fill=TEXT2, font=F_XS)
    d.text((mx+80, ey+22), subject, fill=TEXT, font=F_SM)
    d.text((mx+540, ey+13), time, fill=TEXT3, font=F_XS)

# Stats panel
draw_card(d, mx+615, 155, 430, 200, 'ANALYSE EMAIL (7 JOURS)')
mail_data = [0.6+random.gauss(0,0.1) for _ in range(30)]
draw_line_chart(d, mx+615, 175, 430, 170, BLUE, mail_data)

draw_card(d, mx+615, 370, 210, 185, 'PAR CATEGORIE')
draw_donut(d, mx+720, 490, 50, [75,15,10], [GREEN, AMBER, RED])
d.text((mx+625, 400), 'Securise 75%', fill=GREEN, font=F_XS)
d.text((mx+625, 416), 'Spam 15%', fill=AMBER, font=F_XS)
d.text((mx+625, 432), 'Phishing 10%', fill=RED, font=F_XS)

draw_card(d, mx+840, 370, 205, 185, 'ACTIONS')
actions = [('Bloques',47,RED),('Quarantaine',12,AMBER),('Signales',8,PURPLE),('Approuves',1137,GREEN)]
for i,(l,v,c) in enumerate(actions):
    d.text((mx+855, 400+i*36), l, fill=TEXT2, font=F_SM)
    d.text((mx+960, 400+i*36), str(v), fill=c, font=F_MED)

img.save('screenshots/mailshield.png')
print('[OK] mailshield.png')


# ═══════════════════════════════════════════════════════════════
# 4. CLEANGUARD
# ═══════════════════════════════════════════════════════════════
img, d = new_img()
draw_topbar(d, 'CleanGuard Pro', 'Scanner antimalware — Nettoyage systeme', RED)
sidebar_cg = [('🔍','Scan rapide'),('🛡','Scan complet'),('🧹','Nettoyage'),('🔒','Quarantaine'),
              ('📊','Historique'),('⚙','Parametres'),('🔄','Mises a jour'),('📋','Logs')]
draw_sidebar(d, sidebar_cg, 1, RED)

mx = 195
draw_metric(d, mx, 60, 240, '24.3 GB', 'Espace nettoye', GREEN)
draw_metric(d, mx+255, 60, 240, '7', 'Menaces trouvees', RED)
draw_metric(d, mx+510, 60, 240, '12,847', 'Fichiers scannes', BLUE)
draw_metric(d, mx+765, 60, 240, 'CLEAN', 'Statut systeme', GREEN)

# Scan progress
draw_card(d, mx, 155, 850, 120, 'SCAN EN COURS — Analyse heuristique')
d.rounded_rectangle([mx+14, 200, mx+836, 218], radius=6, fill=BG)
d.rounded_rectangle([mx+14, 200, mx+600, 218], radius=6, fill=GREEN)
d.text((mx+14, 225), 'C:\\Windows\\System32\\drivers\\... — 71% complete', fill=TEXT2, font=F_XS)
d.text((mx+650, 203), '8,947 / 12,847 fichiers', fill=TEXT2, font=F_XS)

# Threats found
draw_card(d, mx, 290, 520, 280, 'MENACES DETECTEES')
threats_cg = [
    ('Trojan.Win32.Agent', 'C:\\Users\\temp\\suspicious.exe', 'Critique', RED),
    ('Adware.BrowserHijack', 'C:\\Program Files\\toolbar.dll', 'Moyen', AMBER),
    ('PUP.Optional.InstallCore', 'C:\\Downloads\\setup.exe', 'Faible', AMBER),
    ('Worm.VBS.Agent', 'C:\\Users\\Public\\script.vbs', 'Critique', RED),
    ('Riskware.Miner', 'C:\\Temp\\miner.exe', 'Eleve', RED),
    ('Adware.Popup', 'C:\\AppData\\popup.dll', 'Faible', AMBER),
    ('Backdoor.MSIL', 'C:\\Windows\\Temp\\svc.exe', 'Critique', RED),
]
for i, (name, path, sev, c) in enumerate(threats_cg[:7]):
    ty = 320 + i * 34
    d.rounded_rectangle([mx+14, ty, mx+70, ty+20], radius=3, fill=(*c[:3],40))
    d.text((mx+18, ty+4), sev[:4], fill=c, font=F_XS)
    d.text((mx+80, ty+4), name, fill=TEXT, font=F_SM)
    d.text((mx+280, ty+4), path[:35], fill=TEXT3, font=F_XS)

# Cleanup stats
draw_card(d, mx+535, 290, 310, 280, 'NETTOYAGE')
clean_items = [('Cache navigateurs','4.2 GB',BLUE),('Fichiers temp','8.1 GB',PURPLE),
               ('Logs systeme','2.8 GB',GREEN),('Corbeille','5.3 GB',AMBER),
               ('MaJ Windows','3.9 GB',RED)]
for i,(l,v,c) in enumerate(clean_items):
    cy = 320+i*48
    bw = int(random.uniform(100,260))
    d.text((mx+550, cy), l, fill=TEXT2, font=F_SM)
    d.text((mx+550, cy+18), v, fill=c, font=F_MED)
    d.rounded_rectangle([mx+700, cy+8, mx+700+bw, cy+22], radius=3, fill=c)

img.save('screenshots/cleanguard.png')
print('[OK] cleanguard.png')


# ═══════════════════════════════════════════════════════════════
# 5. SENTINEL OS
# ═══════════════════════════════════════════════════════════════
img, d = new_img()
draw_topbar(d, 'Sentinel OS — Cortex', 'SOAR & Threat Intelligence Platform', PURPLE)
sidebar_s = [('🧠','Cortex'),('📡','Agents (9)'),('📋','Playbooks'),('🌍','Threat Intel'),
             ('🔔','Alertes'),('📊','Dashboard'),('🗺','Carte'),('⚙','Config')]
draw_sidebar(d, sidebar_s, 0, PURPLE)

mx = 195
draw_metric(d, mx, 60, 240, '9/9', 'Agents connectes', GREEN)
draw_metric(d, mx+255, 60, 240, '3', 'Playbooks actifs', PURPLE)
draw_metric(d, mx+510, 60, 240, '47,230', 'IOCs charges', AMBER)
draw_metric(d, mx+765, 60, 240, '99.8%', 'Uptime systeme', GREEN)

# Agent status grid
draw_card(d, mx, 155, 530, 250, 'AGENTS STATUS')
agents = [('NetGuard',8765,GREEN),('MailShield',8800,GREEN),('CleanGuard',8810,GREEN),
          ('VPNGuard',8820,GREEN),('Honeypot',8830,GREEN),('FIM',8840,GREEN),
          ('StrikeBack',8850,GREEN),('Recorder',8860,GREEN),('Cortex',8900,BLUE)]
for i, (name, port, c) in enumerate(agents):
    row, col = i // 3, i % 3
    ax = mx + 14 + col * 172
    ay = 185 + row * 70
    d.rounded_rectangle([ax, ay, ax+160, ay+58], radius=8, fill=BG3, outline=(*c[:3],60))
    d.ellipse([ax+10, ay+20, ax+22, ay+32], fill=c)
    d.text((ax+30, ay+10), name, fill=TEXT, font=F_SM)
    d.text((ax+30, ay+28), f'Port {port} — Active', fill=c, font=F_XS)

# Threat timeline
draw_card(d, mx+545, 155, 500, 250, 'TIMELINE DES MENACES (24H)')
for i in range(48):
    bx = mx + 560 + i * 10
    bh = random.randint(5, 120)
    c = RED if bh > 80 else (AMBER if bh > 40 else GREEN)
    d.rectangle([bx, 375-bh, bx+7, 375], fill=c)
d.text((mx+560, 385), '00:00', fill=TEXT3, font=F_XS)
d.text((mx+800, 385), '12:00', fill=TEXT3, font=F_XS)
d.text((mx+1020, 385), '23:59', fill=TEXT3, font=F_XS)

# Playbooks
draw_card(d, mx, 420, 345, 220, 'PLAYBOOKS ACTIFS')
pbs = [('Auto-Block Port Scan','12 exec','Active',GREEN),
       ('Quarantine Malware','8 exec','Active',GREEN),
       ('Alert DDoS > 10k pps','3 exec','Active',GREEN),
       ('Isolate Lateral Move','1 exec','Standby',AMBER)]
for i,(name,ex,st,c) in enumerate(pbs):
    py = 450 + i * 44
    d.rounded_rectangle([mx+14, py, mx+330, py+36], radius=6, fill=BG3)
    d.text((mx+24, py+4), name, fill=TEXT, font=F_SM)
    d.text((mx+24, py+20), ex, fill=TEXT3, font=F_XS)
    d.rounded_rectangle([mx+250, py+8, mx+320, py+28], radius=4, fill=(*c[:3],30))
    d.text((mx+258, py+11), st, fill=c, font=F_XS)

# Threat Intel
draw_card(d, mx+360, 420, 340, 220, 'THREAT INTEL FEEDS')
feeds = [('AbuseIPDB','12,450 IPs',GREEN),('OTX AlienVault','28,100 IOCs',GREEN),
         ('Spamhaus DROP','5,200 nets',GREEN),('VirusTotal','1,480 hashes',AMBER)]
for i,(name,count,c) in enumerate(feeds):
    fy = 450 + i * 44
    d.rounded_rectangle([mx+374, fy, mx+685, fy+36], radius=6, fill=BG3)
    d.ellipse([mx+384, fy+12, mx+396, fy+24], fill=c)
    d.text((mx+404, fy+4), name, fill=TEXT, font=F_SM)
    d.text((mx+404, fy+20), count, fill=TEXT2, font=F_XS)

# Recent alerts
draw_card(d, mx+715, 420, 330, 220, 'ALERTES RECENTES')
alerts = [('Port scan depuis 185.220.x','Critique',RED),
          ('Brute force SSH detecte','Eleve',RED),
          ('Fichier modifie: /etc/passwd','Moyen',AMBER),
          ('Nouveau device sur LAN','Info',BLUE),
          ('Tunnel DNS suspect','Eleve',RED)]
for i,(msg,sev,c) in enumerate(alerts):
    ay = 450 + i * 38
    d.text((mx+725, ay+4), f'{14-i}:0{i}', fill=TEXT3, font=F_XS)
    d.rounded_rectangle([mx+775, ay+2, mx+820, ay+18], radius=3, fill=(*c[:3],30))
    d.text((mx+780, ay+4), sev[:4], fill=c, font=F_XS)
    d.text((mx+825, ay+4), msg[:28], fill=TEXT2, font=F_XS)

img.save('screenshots/sentinel.png')
print('[OK] sentinel.png')


# ═══════════════════════════════════════════════════════════════
# 6. VPNGUARD
# ═══════════════════════════════════════════════════════════════
img, d = new_img()
draw_topbar(d, 'VPNGuard + WireGuard', 'VPN Manager — Tunnel chiffre', GREEN)
sidebar_v = [('🔒','Tunnel VPN'),('👥','Peers'),('📊','Monitoring'),('🔑','Cles'),
             ('⚙','Configuration'),('📋','Logs')]
draw_sidebar(d, sidebar_v, 0, GREEN)

mx = 195
draw_metric(d, mx, 60, 240, 'WG0', 'Interface active', GREEN)
draw_metric(d, mx+255, 60, 240, '3', 'Peers connectes', BLUE)
draw_metric(d, mx+510, 60, 240, '51820', 'Port ecoute', PURPLE)
draw_metric(d, mx+765, 60, 240, '2.4 GB', 'Transfert total', AMBER)

# Tunnel status
draw_card(d, mx, 155, 530, 180, 'TUNNEL WIREGUARD — ACTIF')
d.rounded_rectangle([mx+14, 185, mx+140, 210], radius=6, fill=(16,80,40))
d.text((mx+24, 189), 'CONNECTED', fill=GREEN, font=F_SM)
d.text((mx+14, 220), 'Interface: wg0', fill=TEXT, font=F_SM)
d.text((mx+14, 240), 'Adresse: 10.66.66.1/24', fill=TEXT2, font=F_SM)
d.text((mx+14, 260), 'Endpoint: vpn.netguard.pro:51820', fill=TEXT2, font=F_SM)
d.text((mx+14, 280), 'DNS: 1.1.1.1, 9.9.9.9', fill=TEXT2, font=F_SM)
d.text((mx+300, 220), 'Uptime: 14h 32m', fill=GREEN, font=F_SM)
d.text((mx+300, 240), 'Handshake: 12s ago', fill=TEXT2, font=F_SM)
d.text((mx+300, 260), 'TX: 1.8 GB  /  RX: 0.6 GB', fill=TEXT2, font=F_SM)

# Peers
draw_card(d, mx+545, 155, 500, 180, 'PEERS CONNECTES')
peers = [('Laptop Bureau','10.66.66.2','1.2 GB','Active',GREEN),
         ('iPhone Pro','10.66.66.3','450 MB','Active',GREEN),
         ('Serveur Backup','10.66.66.4','800 MB','Active',GREEN)]
for i,(name,ip,transfer,st,c) in enumerate(peers):
    py = 185 + i * 48
    d.rounded_rectangle([mx+559, py, mx+1030, py+40], radius=6, fill=BG3)
    d.ellipse([mx+569, py+14, mx+581, py+26], fill=c)
    d.text((mx+590, py+4), name, fill=TEXT, font=F_SM)
    d.text((mx+590, py+22), f'{ip} — {transfer}', fill=TEXT2, font=F_XS)
    d.rounded_rectangle([mx+950, py+8, mx+1020, py+28], radius=4, fill=(*c[:3],30))
    d.text((mx+960, py+11), st, fill=c, font=F_XS)

# Bandwidth chart
draw_card(d, mx, 350, 1050, 250, 'BANDE PASSANTE VPN (24H)')
vpn_data = [0.3+0.4*math.sin(i*0.08)+random.gauss(0,0.08) for i in range(80)]
draw_line_chart(d, mx, 370, 1050, 220, GREEN, vpn_data)

img.save('screenshots/vpnguard.png')
print('[OK] vpnguard.png')


# ═══════════════════════════════════════════════════════════════
# 7-15: Simpler unique dashboards
# ═══════════════════════════════════════════════════════════════

# 7. ANALYZE
img, d = new_img()
draw_topbar(d, 'NetGuard Analyze', 'Deep Packet Inspection — Forensique', PURPLE)
draw_card(d, 20, 60, 200, H-70)
d.text((34, 75), 'FICHIERS CHARGES', fill=TEXT2, font=F_XS)
files = ['capture_2026-03.pcap','alert_log.json','traffic_dump.csv']
for i,f in enumerate(files):
    d.rounded_rectangle([30, 100+i*40, 210, 130+i*40], radius=5, fill=BG3)
    d.text((40, 108+i*40), f, fill=BLUE, font=F_XS)

draw_card(d, 235, 60, 530, 300, 'ANALYSE DPI — PAYLOAD INSPECTION')
# Hex dump look
for i in range(10):
    y = 90 + i * 24
    addr = f'0x{i*16:04X}'
    hexd = ' '.join([f'{random.randint(0,255):02X}' for _ in range(16)])
    d.text((250, y), addr, fill=PURPLE, font=F_XS)
    d.text((310, y), hexd, fill=TEXT2, font=F_XS)

draw_card(d, 780, 60, 480, 300, 'PROTOCOLES DETECTES')
protos = [('TLS 1.3',45,BLUE),('HTTP/2',25,GREEN),('DNS',15,AMBER),('SSH',10,PURPLE),('QUIC',5,RED)]
for i,(p,v,c) in enumerate(protos):
    py = 90+i*50
    bw = int(v*4)
    d.text((800, py), p, fill=TEXT, font=F_SM)
    d.text((800, py+18), f'{v}%', fill=c, font=F_XS)
    d.rounded_rectangle([880, py+8, 880+bw, py+22], radius=3, fill=c)

draw_card(d, 235, 375, 1025, 280, 'FINGERPRINTS JA3/TLS')
ja3 = [('e7d705a3286e19ea42f587b344ee6865','Chrome 120','Google',GREEN),
       ('a0e9f5d64349fb13c83a4ea3f09b04d1','Firefox 121','Mozilla',GREEN),
       ('bd0bf25947d4a37404f0424edf4db9ad','Python requests','Unknown',AMBER),
       ('c12f54a256789de0','Cobalt Strike','Malicious',RED),
       ('f48c1ba24e120d0a','Metasploit','Malicious',RED)]
for i,(hash,client,org,c) in enumerate(ja3):
    jy = 405+i*48
    d.rounded_rectangle([249, jy, 1245, jy+40], radius=5, fill=BG3)
    d.text((260, jy+4), hash[:24]+'...', fill=TEXT3, font=F_XS)
    d.text((530, jy+4), client, fill=TEXT, font=F_SM)
    d.text((530, jy+22), org, fill=TEXT2, font=F_XS)
    d.rounded_rectangle([1140, jy+8, 1230, jy+30], radius=4, fill=(*c[:3],30))
    d.text((1150, jy+12), 'Safe' if c==GREEN else ('Warn' if c==AMBER else 'ALERT'), fill=c, font=F_XS)

img.save('screenshots/netguard_analyze.png')
print('[OK] netguard_analyze.png')

# 8. HISTORY
img, d = new_img()
draw_topbar(d, 'NetGuard History', 'Historique des evenements et alertes', AMBER)
draw_metric(d, 20, 60, 300, '7,421', 'Evenements totaux', AMBER)
draw_metric(d, 335, 60, 300, '342', 'Alertes', RED)
draw_metric(d, 650, 60, 300, '99.2%', 'Uptime 30 jours', GREEN)
draw_metric(d, 965, 60, 300, '30 j', 'Retention', BLUE)

draw_card(d, 20, 155, W-40, 200, 'TIMELINE DES EVENEMENTS')
for i in range(100):
    bx = 35 + i * 12
    bh = random.randint(3, 150)
    c = RED if bh > 120 else (AMBER if bh > 60 else GREEN)
    d.rectangle([bx, 330-bh, bx+8, 330], fill=c)

draw_card(d, 20, 370, W-40, 300, 'JOURNAL DES ALERTES')
events = [
    ('2026-03-27 14:32:01','CRITICAL','Port scan 185.220.101.5 → 445,3389,22,80',RED),
    ('2026-03-27 14:28:45','HIGH','Brute force SSH depuis 91.134.22.18 (47 tentatives)',RED),
    ('2026-03-27 14:15:20','MEDIUM','Requete DNS suspecte: evil-domain.ru',AMBER),
    ('2026-03-27 13:58:10','HIGH','Payload SQLi detecte dans HTTP POST',RED),
    ('2026-03-27 13:42:33','LOW','Nouveau device LAN: 192.168.1.105 (Samsung)',BLUE),
    ('2026-03-27 13:30:00','MEDIUM','Trafic inhabituel port 8443 (+300%)',AMBER),
    ('2026-03-27 13:15:47','INFO','Backup automatique termine (2.3 MB)',GREEN),
    ('2026-03-27 12:58:22','HIGH','Tentative XSS dans parametre URL',RED),
]
for i,(ts,sev,msg,c) in enumerate(events):
    ey = 400+i*34
    d.text((35, ey), ts, fill=TEXT3, font=F_XS)
    d.rounded_rectangle([200, ey-2, 270, ey+16], radius=3, fill=(*c[:3],30))
    d.text((207, ey), sev, fill=c, font=F_XS)
    d.text((280, ey), msg[:70], fill=TEXT2, font=F_SM)

img.save('screenshots/netguard_history.png')
print('[OK] netguard_history.png')

# 9. NETWORK
img, d = new_img()
draw_topbar(d, 'NetGuard Network', 'Scan LAN — Decouverte de peripheriques', GREEN)
draw_metric(d, 20, 60, 300, '24', 'Peripheriques', GREEN)
draw_metric(d, 335, 60, 300, '3', 'Serveurs', BLUE)
draw_metric(d, 650, 60, 300, '5', 'Inconnus', RED)
draw_metric(d, 965, 60, 300, '192.168.1.0/24', 'Sous-reseau', PURPLE)

draw_card(d, 20, 155, W-40, 500, 'PERIPHERIQUES RESEAU')
devices = [
    ('192.168.1.1','Gateway','Cisco Router','Active',GREEN,'Router'),
    ('192.168.1.10','Desktop-PC','Windows 11','Active',GREEN,'PC'),
    ('192.168.1.15','MacBook-Pro','macOS 14','Active',GREEN,'Mac'),
    ('192.168.1.20','NAS-Synology','Linux DSM 7','Active',GREEN,'NAS'),
    ('192.168.1.25','iPhone-Pro','iOS 17','Active',GREEN,'Phone'),
    ('192.168.1.30','Imprimante','HP LaserJet','Active',BLUE,'Printer'),
    ('192.168.1.35','Camera-IP','Hikvision','Active',AMBER,'Camera'),
    ('192.168.1.40','Smart-TV','Samsung Tizen','Idle',TEXT3,'TV'),
    ('192.168.1.100','Unknown-1','???','Active',RED,'???'),
    ('192.168.1.105','Unknown-2','???','New',RED,'???'),
]
headers = ['IP','Hostname','OS / Type','Status','Fingerprint']
for j,h in enumerate(headers):
    d.text((35+j*240, 185), h, fill=TEXT2, font=F_MED)
d.line([(35,205),(W-55,205)], fill=BORDER)

for i,(ip,host,os_t,st,c,fp) in enumerate(devices):
    dy = 215+i*44
    if i%2==0: d.rectangle([25, dy-2, W-45, dy+38], fill=BG3)
    d.ellipse([40, dy+12, 52, dy+24], fill=c)
    d.text((60, dy+8), ip, fill=TEXT, font=F_SM)
    d.text((300, dy+8), host, fill=TEXT2, font=F_SM)
    d.text((540, dy+8), os_t, fill=TEXT2, font=F_SM)
    d.rounded_rectangle([780, dy+6, 840, dy+26], radius=4, fill=(*c[:3],30))
    d.text((786, dy+9), st, fill=c, font=F_XS)
    d.text((860, dy+8), fp, fill=TEXT3, font=F_SM)

img.save('screenshots/netguard_network.png')
print('[OK] netguard_network.png')

# 10-15: More dashboards with unique layouts
for name, title, sub, accent, content_fn in [
    ('netguard_panels.png', 'NetGuard Panels', 'Vue multi-ecrans detachable', BLUE, 'panels'),
    ('netguard_service.png', 'NetGuard Service', 'Status des 9 services', GREEN, 'service'),
    ('honeypot.png', 'Honeypot', 'Faux services — Pieges a attaquants', AMBER, 'honeypot'),
    ('fim.png', 'FIM', 'File Integrity Monitor — SHA-256', BLUE, 'fim'),
    ('recorder.png', 'Recorder', 'Forensic PCAP — Capture de sessions', PURPLE, 'recorder'),
    ('strikeback.png', 'StrikeBack', 'Reponse active aux attaques', RED, 'strikeback'),
]:
    img, d = new_img()
    draw_topbar(d, title, sub, accent)

    if content_fn == 'panels':
        # 4 mini dashboards in quadrants
        for qi in range(4):
            qx = 20 + (qi%2)*630
            qy = 60 + (qi//2)*320
            draw_card(d, qx, qy, 620, 305)
            labels = ['Trafic Reseau','Menaces Live','Protocoles','Geo-IP']
            d.text((qx+14, qy+10), labels[qi], fill=accent, font=F_MED)
            if qi == 0:
                data = [0.4+0.3*math.sin(i*0.2)+random.gauss(0,0.05) for i in range(40)]
                draw_line_chart(d, qx, qy+30, 620, 260, BLUE, data)
            elif qi == 1:
                for j in range(12):
                    bx = qx+20+j*48
                    bh = random.randint(20,240)
                    c = RED if bh>180 else (AMBER if bh>100 else GREEN)
                    d.rectangle([bx, qy+280-bh, bx+35, qy+280], fill=c)
            elif qi == 2:
                draw_donut(d, qx+310, qy+170, 80, [35,25,20,12,8], [BLUE,GREEN,PURPLE,AMBER,RED])
            else:
                draw_donut(d, qx+310, qy+170, 80, [30,22,18,15,15], [RED,AMBER,BLUE,PURPLE,GREEN])

    elif content_fn == 'service':
        services = [('NetGuard Pro',8765,'Running','14h 32m'),('MailShield',8800,'Running','14h 30m'),
                    ('CleanGuard',8810,'Running','14h 28m'),('Sentinel OS',8900,'Running','14h 25m'),
                    ('VPNGuard',8820,'Running','14h 20m'),('Honeypot',8830,'Running','14h 18m'),
                    ('FIM',8840,'Running','14h 15m'),('Recorder',8860,'Running','14h 10m'),
                    ('StrikeBack',8850,'Stopped','—')]
        draw_card(d, 20, 60, W-40, 600)
        for j,h in enumerate(['Service','Port','Status','Uptime','CPU','RAM']):
            d.text((35+j*200, 80), h, fill=TEXT2, font=F_MED)
        d.line([(35,100),(W-55,100)], fill=BORDER)
        for i,(svc,port,st,up) in enumerate(services):
            sy = 110+i*58
            if i%2==0: d.rectangle([25,sy,W-45,sy+50], fill=BG3)
            c = GREEN if st=='Running' else RED
            d.ellipse([40, sy+18, 52, sy+30], fill=c)
            d.text((60, sy+14), svc, fill=TEXT, font=F_SM)
            d.text((260, sy+14), str(port), fill=TEXT2, font=F_SM)
            d.rounded_rectangle([460, sy+12, 530, sy+32], radius=4, fill=(*c[:3],30))
            d.text((468, sy+15), st, fill=c, font=F_XS)
            d.text((660, sy+14), up, fill=TEXT2, font=F_SM)
            cpu = random.randint(1,15) if st=='Running' else 0
            ram = random.randint(30,180) if st=='Running' else 0
            d.text((860, sy+14), f'{cpu}%', fill=(GREEN if cpu<10 else AMBER), font=F_SM)
            d.text((1060, sy+14), f'{ram} MB', fill=TEXT2, font=F_SM)

    elif content_fn == 'honeypot':
        draw_metric(d, 20, 60, 300, '5', 'Services actifs', GREEN)
        draw_metric(d, 335, 60, 300, '127', 'Attaquants pieges', RED)
        draw_metric(d, 650, 60, 300, 'SSH', 'Top piege', AMBER)
        draw_metric(d, 965, 60, 300, '48h', 'Uptime', BLUE)
        draw_card(d, 20, 155, 620, 250, 'SERVICES HONEYPOT')
        svcs = [('SSH (22)','Active','43 hits',GREEN),('FTP (21)','Active','28 hits',GREEN),
                ('RDP (3389)','Active','31 hits',GREEN),('HTTP (8080)','Active','18 hits',GREEN),
                ('Telnet (23)','Active','7 hits',GREEN)]
        for i,(s,st,h,c) in enumerate(svcs):
            sy = 185+i*42
            d.rounded_rectangle([34, sy, 626, sy+35], radius=6, fill=BG3)
            d.ellipse([44, sy+11, 56, sy+23], fill=c)
            d.text((65, sy+9), s, fill=TEXT, font=F_SM)
            d.text((400, sy+9), h, fill=AMBER, font=F_SM)
        draw_card(d, 660, 155, 600, 250, 'ATTAQUES RECENTES')
        for i in range(6):
            ay = 185+i*36
            d.text((674, ay), f'185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}', fill=RED, font=F_XS)
            d.text((810, ay), random.choice(['SSH brute','FTP login','RDP scan','HTTP probe']), fill=TEXT2, font=F_XS)
            d.text((980, ay), f'{random.randint(1,59)}m ago', fill=TEXT3, font=F_XS)
            d.rounded_rectangle([1100, ay-2, 1170, ay+16], radius=3, fill=(*RED[:3],30))
            d.text((1108, ay), 'Blocked', fill=RED, font=F_XS)
        draw_card(d, 20, 420, W-40, 240, 'TRAP FILES ACTIVITY')
        trap_data = [random.gauss(0.3,0.15) for _ in range(60)]
        draw_line_chart(d, 20, 440, W-40, 210, AMBER, trap_data)

    elif content_fn == 'fim':
        draw_metric(d, 20, 60, 300, '2,847', 'Fichiers surveilles', BLUE)
        draw_metric(d, 335, 60, 300, '3', 'Modifies', RED)
        draw_metric(d, 650, 60, 300, 'SHA-256', 'Algorithme', PURPLE)
        draw_metric(d, 965, 60, 300, 'SECURE', 'Status', GREEN)
        draw_card(d, 20, 155, W-40, 500, 'SURVEILLANCE DES FICHIERS')
        ffiles = [('/etc/passwd','Unchanged','a1b2c3d4e5f6...','2026-03-27 08:00',GREEN),
                  ('/etc/shadow','Unchanged','f6e5d4c3b2a1...','2026-03-27 08:00',GREEN),
                  ('C:\\Windows\\System32\\drivers\\etc\\hosts','MODIFIED','changed→9x8y7z...','2026-03-27 14:15',RED),
                  ('/var/log/auth.log','Unchanged','1a2b3c4d5e6f...','2026-03-27 12:30',GREEN),
                  ('C:\\Windows\\System32\\config\\SAM','MODIFIED','old→new_hash...','2026-03-27 13:42',RED),
                  ('/etc/ssh/sshd_config','Unchanged','abcdef123456...','2026-03-27 08:00',GREEN),
                  ('C:\\Program Files\\startup.bat','MODIFIED','deleted content','2026-03-27 11:20',RED),
                  ('/opt/netguard-pro/netguard.py','Unchanged','789abc012def...','2026-03-27 08:00',GREEN)]
        for j,h in enumerate(['Fichier','Status','Hash SHA-256','Dernier check']):
            d.text((35+j*300, 175), h, fill=TEXT2, font=F_MED)
        d.line([(35,195),(W-55,195)], fill=BORDER)
        for i,(f,st,hs,ts,c) in enumerate(ffiles):
            fy = 205+i*50
            if i%2==0: d.rectangle([25,fy,W-45,fy+42], fill=BG3)
            d.text((35, fy+12), f[:35], fill=TEXT, font=F_SM)
            d.rounded_rectangle([335, fy+10, 425, fy+30], radius=4, fill=(*c[:3],30))
            d.text((343, fy+13), st[:10], fill=c, font=F_XS)
            d.text((635, fy+12), hs[:20], fill=TEXT3, font=F_XS)
            d.text((935, fy+12), ts, fill=TEXT2, font=F_XS)

    elif content_fn == 'recorder':
        draw_metric(d, 20, 60, 300, '4.2 GB', 'Capture totale', PURPLE)
        draw_metric(d, 335, 60, 300, '23', 'Sessions', BLUE)
        draw_metric(d, 650, 60, 300, 'PCAP', 'Format', GREEN)
        draw_metric(d, 965, 60, 300, 'Active', 'Enregistrement', GREEN)
        draw_card(d, 20, 155, W-40, 250, 'SESSIONS ENREGISTREES')
        sessions = [('session_001.pcap','2026-03-27 09:00','14:32','342 MB','12,847 pkts'),
                    ('session_002.pcap','2026-03-27 10:30','11:45','189 MB','8,421 pkts'),
                    ('session_003.pcap','2026-03-26 08:00','24:00','1.2 GB','45,320 pkts'),
                    ('session_004.pcap','2026-03-25 14:00','06:30','890 MB','28,100 pkts'),
                    ('session_005.pcap','2026-03-25 08:00','05:15','650 MB','19,800 pkts')]
        for j,h in enumerate(['Fichier','Date','Duree','Taille','Paquets']):
            d.text((35+j*240, 175), h, fill=TEXT2, font=F_MED)
        d.line([(35,195),(W-55,195)], fill=BORDER)
        for i,(f,dt,dur,sz,pk) in enumerate(sessions):
            ry = 205+i*40
            if i%2==0: d.rectangle([25,ry,W-45,ry+34], fill=BG3)
            d.text((35, ry+8), f, fill=PURPLE, font=F_SM)
            d.text((275, ry+8), dt, fill=TEXT2, font=F_SM)
            d.text((515, ry+8), dur, fill=TEXT2, font=F_SM)
            d.text((755, ry+8), sz, fill=AMBER, font=F_SM)
            d.text((995, ry+8), pk, fill=TEXT2, font=F_SM)
        draw_card(d, 20, 420, W-40, 240, 'BANDE PASSANTE CAPTURE')
        rec_data = [0.2+0.5*abs(math.sin(i*0.1))+random.gauss(0,0.05) for i in range(60)]
        draw_line_chart(d, 20, 440, W-40, 210, PURPLE, rec_data)

    elif content_fn == 'strikeback':
        draw_metric(d, 20, 60, 300, '47', 'IPs bloquees', RED)
        draw_metric(d, 335, 60, 300, '12', 'Tarpit actifs', AMBER)
        draw_metric(d, 650, 60, 300, '5', 'Decoys deployes', PURPLE)
        draw_metric(d, 965, 60, 300, 'ARMED', 'Mode defense', GREEN)
        draw_card(d, 20, 155, 620, 300, 'REPONSES ACTIVES')
        responses = [('Auto-Block','185.220.101.5','Port scan detecte','Bloque 24h',RED),
                     ('Tarpit','91.134.22.18','Brute force SSH','Ralenti x100',AMBER),
                     ('Decoy','103.224.80.1','HTTP probe','Redirige leurre',PURPLE),
                     ('Auto-Block','5.188.86.12','Payload SQLi','Bloque permanent',RED),
                     ('Tarpit','45.33.32.156','DNS tunnel','Ralenti x50',AMBER),
                     ('Auto-Block','123.45.67.89','XSS attempt','Bloque 48h',RED)]
        for i,(action,ip,reason,result,c) in enumerate(responses):
            ry = 185+i*42
            d.rounded_rectangle([34, ry, 626, ry+35], radius=6, fill=BG3)
            d.rounded_rectangle([44, ry+8, 120, ry+28], radius=4, fill=(*c[:3],30))
            d.text((50, ry+11), action, fill=c, font=F_XS)
            d.text((130, ry+9), ip, fill=TEXT, font=F_SM)
            d.text((300, ry+9), reason[:20], fill=TEXT2, font=F_XS)
            d.text((480, ry+9), result, fill=c, font=F_XS)
        draw_card(d, 660, 155, 600, 300, 'DANGER SCORE PAR IP')
        draw_bar_chart(d, 660, 180, 600, 265, [RED,RED,RED,AMBER,AMBER,AMBER,BLUE,BLUE],
                       data=[95,88,82,65,58,45,30,20])
        draw_card(d, 20, 470, W-40, 200, 'TIMELINE REPONSES (24H)')
        sb_data = [random.gauss(0.3,0.2) for _ in range(60)]
        draw_line_chart(d, 20, 490, W-40, 170, RED, sb_data)

    img.save(f'screenshots/{name}')
    print(f'[OK] {name}')

print('\n=== 15 screenshots uniques generes ===')
