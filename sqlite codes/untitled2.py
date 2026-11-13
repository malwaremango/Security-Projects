import sqlite3 # library for å intialiserer sqlite i python

#eksempel fra forelesning 

# Oppretter en database i minnet
db = sqlite3.connect(':memory:') 

# Lager tabellen (CREATE TABLE)
db.execute('CREATE TABLE pizzas (id INTEGER PRIMARY KEY, name TEXT, price INTEGER)')
#db.execute('CREATE TABLE person (id INTEGER PRIMARY KEY, name TEXT, age INTEGER)')

#
# Legger inn data ((INSERT INTO (table name)


db.execute('''
    INSERT INTO pizzas VALUES 
    (1, 'Mozarella', 129), 
    (2, 'Cheese Pizza', 400)
    
''')
rows0 = db.execute("SELECT * FROM pizzas").fetchall()
print(rows0)


db.execute('''
    INSERT INTO person VALUES 
    (1, 'Bob', 12), 
    (2, 'Alice', 53), 
    (3, 'Jason', 24),
    (4, 'Noah', 87)
    
''')


# Henter og skriver ut data #execute kjører sql spørringene (statement)

#row = db.execute("DELETE FROM person WHERE id =4")
rows0 = db.execute("SELECT * FROM person WHERE age < 30").fetchall()  #Hva betyr spørringen?

print(rows0)

#rows = db.execute("UPDATE person SET age= 98  WHERE id= 3 ").fetchall() # 

#sql ="INSERT INTO person VALUES (?, ?, ?)"
#row2 = db.execute(sql , (5,"kali" , 65))
#row3  = db.execute(sql , (6, "jojo", 654))
rows5 = db.execute("Select * From person").fetchall()
#print(rows)
#print(rows5)

