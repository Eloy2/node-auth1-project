const express = require("express")
const db = require("./users-model")
const bcrypt = require("bcryptjs")
const session = require("express-session")
const KnexSessionStore = require("connect-session-knex")(session)
const dbConfig = require("./config")
const { Server } = require("http")

const server = express()

const port = process.env.PORT || 5000

server.use(express.json())
server.use(session({
    resave: false, // avoids recreating sessions that have not changed
    saveUninitialized: false, // comply with GDPR laws
    secret: "sercet",
    store: new KnexSessionStore({
        knex: dbConfig, // configured instance of knex, or live database connection
        createtable: true, // if the session does not exist, create it
    }),
}))

server.get("/users", restrict, async (req, res) => {
    try{
        const users = await db.getusers()
        res.json(users)  

    } catch(err) {
        console.log(err)
        res.status(500).json({ message: "Something went wrong"})
    }
}) 

server.post("/users", async (req, res) => {
    try{
        const { username, password } = req.body

        const newUser = await db.adduser({
            username,
            // hash the password with a time complexity of 15 (will take around 2 seconds on my current machine)
            password: await bcrypt.hash(password, 15),
        })

        res.json(newUser)
    } catch(err) {
        console.log(err)
        res.status(500).json({ message: "Something went wrong"})
    }
}) 

server.post("/login", async (req, res) => {
    try{
        const { username, password } = req.body
        const user = await db.findByusername(username)

        // if user is NOT in database
        if(!user) {
            return res.status(401).json({ message: "You shall not pass!"})
        }

        // compare the password the client is sending with the one in our database
        const passwordValid = await bcrypt.compare(password, user.password)

        // if password is WRONG
        if(!passwordValid) {
            return res.status(401).json({ message: "You shall not pass!"})
        }

        // generate new session for this user
        // and send back a session ID
        req.session.user = user

        res.json({ 
            message: `welcome ${user.username}`,
            userID: req.session.user.id // sent back user id from cookie because it was requested in MVP
        })
    } catch(err) {
        console.log(err)
        res.status(500).json({ message: "Something went wrong"})
    }
}) 

server.get("/logout", async (req, res) => {
    try{
        req.session.destroy((err) => {
            if (err) {
                console.log(err)
                res.status(500).json({ message: "could not logout correctly"})
            } else {
                res.status(200).json({ message: "You have logged out."})
            }
        })
    } catch(err) {
        console.log(err)
        res.status(500).json({ message: "Something went wrong"})
    }
}) 

// MIDDELWARE
function restrict(req, res, next) {
    try {
        // cehck for session 
        if (!req.session || !req.session.user) {
            return res.status(401).json({ message: "You shall not pass!"})
        }

        next()
    } catch(err) {
        console.log(err)
        res.status(500).json({ message: "Something went wrong"})
    }

}

server.listen(port, () => {
    console.log(`Running at http://localhost:${port}`)
})
