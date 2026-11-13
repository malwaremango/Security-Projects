# -*- coding: utf-8 -*-
"""
Created on Mon Nov  9 13:43:22 2026

@author: usah5
"""

import sqlite3 # library for å intialiserer sqlite i python


# Oppretter en database i minnet ((VIKTIG))
db = sqlite3.connect(':memory:') 

# Lager tabellen (CREATE TABLE)

db.execute('CREATE TABLE cars (id INTEGER PRIMARY KEY, BRAND TEXT,  MODEL TEXT, year INTEGER)')

# Legger inn data ((INSERT INTO (table name)

#db.execute kjører sql spørringer
db.execute('''
    INSERT INTO cars VALUES 
    (1, 'Tesla', 'Model 3 ', 2019 ), 
    (2, 'Audi', 'e-tron', 2021),
    (3, 'BMW', 'i4', 2023),
    (4, 'Nissan', 'Leaf', 2018),
    (5, 'Volkswagen', 'ID.4', 2022) , 
    (6, 'Ford', 'Mustang Mach-E', 2021),
    (7, 'Hyundai', 'Ioniq 5', 2022),
    (8, 'Kia', 'EV6', 2023), 
    (9, 'BMW', 'i4', 2023);
    
    
''')

#fetchall() hente ut alle radene som treffer SQL-spørringen din samtidig

rows2 = db.execute("Select * from cars where id =6 ").fetchall()
print(rows2)
#Hvilken spørring sletter EV6 fra tabellen?
print("Spørring som sletter EV6:\n------")
ev6 = db.execute("DELETE FROM cars WHERE id = 8 ")
sql = db.execute("SELECT * FROM cars").fetchall()
print(sql)
#Hvilken spørring henter ut bilmerke og modellnavn for alle biler?

print("Bilmerke og modellnavn for alle biler:\n------")
car = db.execute("SELECT BRAND,MODEL FROM cars ").fetchall()

print(car)
#rows = db.execute("Select * from cars").fetchall()
# Henter og skriver ut data #execute kjører sql spørringene

#print(rows2) #


