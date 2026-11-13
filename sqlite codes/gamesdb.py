# -*- coding: utf-8 -*-
"""
Created on Fri Nov 13 11:58:37 2026

@author: usah5
"""

import sqlite3 # library for å intialiserer sqlite i python


# Oppretter en database i minnet
db = sqlite3.connect(':memory:') 

# Lager tabellen (CREATE TABLE)
db.execute('CREATE TABLE games (id INTEGER PRIMARY KEY, title TEXT, price INTEGER)')


#
# Legger inn data ((INSERT INTO (table name)


db.execute("""
    INSERT INTO games (id, title, price) VALUES 
    
    (1, 'GTA V', 320),
    (2, 'GTA VI', 990),
    (3, 'Tetris', 340),
    (4, 'Wii Sports', 340),
    (5, 'Mario Kart Wii', 370),
    (6, 'Wii Sports', 410),
    (7, 'Assassins Creed IV', 440),
    (8, 'Minecraft', 299),
    (9, 'Red Dead Redemption 2', 499),
    (10, 'The Witcher 3', 399),
    (11, 'Cyberpunk 2077', 450),
    (12, 'Call of Duty Black Ops 6', 699),
    (13, 'Call of Duty Modern Warfare III', 549),
    (14, 'FIFA 25', 599),
    (15, 'EA Sports FC 26', 799),
    (16, 'The Last of Us Part II', 449),
    (17, 'God of War Ragnarok', 499),
    (18, 'Elden Ring', 599),
    (19, 'Dark Souls III', 399),
    (20, 'Resident Evil 4', 499),
    (21, 'Super Mario Odyssey', 449),
    (22, 'Mario Kart 8 Deluxe', 499),
    (23, 'The Legend of Zelda BOTW', 499),
    (24, 'Pokemon Scarlet', 399),
    (25, 'Fortnite', 0),
    (26, 'Rocket League', 0),
    (27, 'The Legend of Zelda Tears Of The Kingdom', 540),
    (28, 'The Legend of Zelda Ocarina Of Time', 590)
    
    
""")

rows0 = db.execute("SELECT * FROM games").fetchall()
#print(rows0)

print("Print alle spill  koster 500 eller mindre  ")
print("\n------------------------------------------------------------")

sql = db.execute(" SELECT * FROM games WHERE price <= 500 ").fetchall()

print(sql)

print("\n------------------------------------------------------------")
print("\n Print et spesifikt spill :")
sql2 = db.execute(" SELECT * FROM games WHERE title = 'GTA VI' ").fetchall()

print(sql2)

print("\n------------------------------------------------------------")
print("Print spill med id 2 og oppover")

sql3 = db.execute("SELECT  title, id from games WHERE id >= 2").fetchall()

# Henter og skriver ut data #execute kjører sql spørringene (statement)

print(sql3)

print("\n------------------------------------------------------------")
print("Print ut gratis spill ")
sql4 = db.execute("SELECT * FROM games WHERE price =0").fetchall()
print(sql4)

print("\n------------------------------------------------------------")
print("Print ut Spill sotert etter dyreste først ")

sql5 = db.execute("SELECT * FROM games ORDER BY price DESC").fetchall()

print(sql5)


print("\n------------------------------------------------------------")
print( "Print ut Spill sotert etter billigste først ")

sql6 = db.execute("SELECT * FROM games ORDER BY price ASC").fetchall()

print(sql6)

print("\n------------------------------------------------------------")
print( "Print ut Spill sotert etter billigste først med limit 3 ")

sql7 = db.execute("SELECT * FROM games ORDER BY price DESC LIMIT 3").fetchall()


print(sql7)

print("\n------------------------------------------------------------")
print(" Finn spillet som har ordet Mario i seg")

sql8 = db.execute("SELECT * FROM games WHERE title LIKE '%zelda%' ").fetchall()

print(sql8)


print("\n------------------------------------------------------------")
print(" Antall ntall spill")

sql9 = db.execute("SELECT COUNT(*) FROM games  ").fetchall()

print(sql9)
#row = db.execute("DELETE FROM person WHERE id =4")


print("Summer prisen på alle spill")
sql10 = db.execute("SELECT SUM(price) FROM games").fetchall()
print(sql10)


print("\n----------------------- ")
print("Print ut spill i alfabetisk rekkefølge ")
sql11= db.execute("SELECT * FROM games GROUP BY title ").fetchall()
print(sql11)


print("\n----------------------- ")
print("Finn de fire dyreste spillene ") #DESC er synkende ASC økende (min-max)
sql12= db.execute("SELECT * FROM games ORDER BY price DESC LIMIT 4 ").fetchall()

print(sql12)



print("\n----------------------- ")
print("Finn spill som koster mellom 300 og 700 (LIMIT 10) ")
sql13 = db.execute("SELECT * FROM games WHERE price BETWEEN 300 AND 700 LIMIT 10 ").fetchall()
print(sql13) 
#UPDATE games SET price = 350 WHERE name = 'GTA V';
#db.execute(DELETE FROM games WHERE id = 3).fetchall()

print("\n----------------------- ")
print("Legg spill i etterkant:")
sql14 ="INSERT INTO games VALUES (?, ?, ?)"
row2 = db.execute(sql14 , (29,"Just Dance 2027" , 400)).fetchall()
sqladd = db.execute("SELECT * FROM games ").fetchall()
print(sqladd)


print("------------------------------------------------------------")
print("End Of File :)")



