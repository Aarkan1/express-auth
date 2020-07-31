const express = require("express")
const app = express()
const acl = require('./acl')
const bcrypt = require('bcrypt')

app.use(express.json())
const port = 3000

const session = require("express-session")

app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // enable frontend debugging
  })
)

// connect to database
const sqlite = require('sqlite3')
const db = new sqlite.Database('./database.db')

// enable async/await on db methods
const util = require("util");
db.all = util.promisify(db.all)
db.get = util.promisify(db.get)
db.runAsync = util.promisify(db.run)

// acl schema at acl.json
app.use(acl)

// add default admin user if it doesn't exist
addDefaultAdmin()
async function addDefaultAdmin() {
  let admin = {
    email: 'admin@admin.com',
    password: await bcrypt.hash('secretpassword', 10)
  }

  let exists = await db.get('SELECT * FROM users WHERE email = ?', admin.email)
  if(exists) return

  db.run('INSERT INTO users(email, password) VALUES(?, ?)', [admin.email, admin.password], function() {
    db.run('INSERT INTO roles(userId, role) VALUES(?, ?)', [this.lastID, 'admin'])
  })
}

app.get('/api/secret', (req, res) => {
  res.json({ secret: 'Only admin can access this secret!' })
})

// whoami
app.get("/api/login", (req, res) => {
  if(req.session.user) {
    res.json(req.session.user)
  } else {
    res.status(400).json({error: 'Not logged in'})
  }
});

// login
app.post("/api/login", async (req, res) => {
  if(req.session.user) {
    return res.json({error: 'Already logged in'})
  }

  const { email, password } = req.body
  let user = await db.get('SELECT * FROM users WHERE email = ?', email)
  
  if(user && (await bcrypt.compare(password, user.password))) {
    // get user roles
    user.roles = (await db.all('SELECT * FROM roles WHERE userId = ?', user.id)).map(r => r.role)

    delete user.password // sanitize password
    req.session.user = {...user}

    res.json(user)
  } else { 
    res.status(400).json({ error: "Failed to login" })
  }
})

// logout
app.get("/api/logout", (req, res) => {
  delete req.session.user
  res.json({ msg: "Logged out" })
})

// register
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body

  let exists = await db.get('SELECT * FROM users WHERE email = ?', email)

  if(exists) {
    return res.status(400).json({ error: "User already exists" })
  }

  let user = {
    email,
    password: await bcrypt.hash(password, 10),
    roles: ['user']
  }

  db.run('INSERT INTO users(email, password) VALUES(?, ?)', [user.email, user.password], async function(err) {
    if(err) {
      return res.status(400).json({ error: 'Register failed' })
    }
    
    for(let role of user.roles) {
      await db.runAsync('INSERT INTO roles(userId, role) VALUES(?, ?)', [this.lastID, role])
    }
    user.id = this.lastID
    delete user.password
    req.session.user = {...user}
    
    res.json(user)
  })
})

// generic get one or many
app.get("/rest/:table/:id?", async (req, res) => {
  const table = req.params.table
  if(table.toLowerCase().includes('select', 'update', 'delete')) {
    return res.status(403).json({ error: 'Found potential SQL injection' })
  }

  let result;
  if (req.params.id) {
    result = await db.get(`SELECT * FROM ${table} WHERE id = ?`, req.params.id);
  } else {
    result = await db.all(`SELECT * FROM ${table}`);
  }
  res.json(result);
})

// generic post
app.post("/rest/:table", async (req, res) => {
  const table = req.params.table
  if(table.toLowerCase().includes('select', 'update', 'delete')) {
    return res.status(403).json({ error: 'Found potential SQL injection' })
  }

  req.body.id && delete req.body.id
  let query = `INSERT INTO ${table}(`
  let body = Object.keys(req.body).reduce((target, param) => {
    query += `${param},`
    target['$' + param] = req.body[param]
    return target
  }, {})

  let columns = Object.keys(body).join(', ')
  query = query.replace(/,$/, `) VALUES(${columns})`)

  db.run(query, body, function(err) {
    if(err) {
      return res.status(400).json({ error: 'Could not insert row' })
    }
    req.body.id = this.lastID
    res.json(req.body);
  })
})

// generic put
app.put("/rest/:table/:id", async (req, res) => {
  const table = req.params.table
  if(table.toLowerCase().includes('select', 'update', 'delete')) {
    return res.status(403).json({ error: 'Found potential SQL injection' })
  }

  let query = `UPDATE ${table} SET `
  let body = Object.keys(req.body).reduce((target, param) => {
    query += `${param} = $${param},`
    target['$' + param] = req.body[param]
    return target
  }, { $id: req.params.id })

  query = query.replace(/,$/, ' WHERE id = $id')

  await db.run(query, body)
  res.json({ success: 'Updated table' });
})

// generic delete
app.delete("/rest/:table/:id", async (req, res) => {
  const { table, id } = req.params
  if(table.toLowerCase().includes('select', 'update', 'delete')) {
    return res.status(403).json({ error: 'Found potential SQL injection' })
  }

  await db.run(`DELETE FROM ${table} WHERE id = ?`, id)
  res.json({ success: `Deleted ${table} with id: ${id}`})
})

app.listen(port, () => console.log("Server running on port: ", port))