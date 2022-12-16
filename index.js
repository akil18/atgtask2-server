const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const port = 5000;

const app = express();
require('dotenv').config();
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.nvyyp05.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true, serverApi: ServerApiVersion.v1 });

// Verify Token
function verifyJWT(req, res, next){
    const authHeader = req.headers.authorization;
    console.log('authHeader', authHeader)
    if(!authHeader){
        res.status(401).send('Unauthorized access');
    }

    const token = authHeader.split(' ')[1];

    console.log('token', token)
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if(err){
            console.log('err', err)
            res.status(403).send('Forbidden access on verify token');
        }
        req.decoded = decoded;
        next();
    });
}

async function run() {
    try{
        const usersCollection = client.db("atgTask2").collection("users");
        const postsCollection = client.db("atgTask2").collection("posts");

        app.get('/users', async (req, res) => {
            const users = await usersCollection.find({}).toArray();
            res.send(users);
        });

        // SIGNUP
        app.post('/signup', async (req, res) => {
            const hashedPassword = await bcrypt.hash(req.body.password, 10);

            const newUser = {
                username: req.body.username,
                email: req.body.email,
                password: hashedPassword
            };

            const result = await usersCollection.insertOne(newUser);
            res.send(result);
        });

        // LOGIN
        app.post('/login', async (req, res) => {
            const username = req.body.username;
            const user = await usersCollection.findOne({username: username});
            if(user == null){
                res.status(401).send('Authentication failed');
            }
            else{
                const isValidPassword = await bcrypt.compare(req.body.password, user.password);
                if(isValidPassword){
                    const token = jwt.sign({username}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '1h'});
                    res.send({accessToken: token});
                }
                else{
                    res.status(401).send('Authentication failed');
                }
            }

        });

        // GET POSTS
        app.get('/posts', async (req, res) => {
            const postsCollection = client.db("atgTask2").collection("posts");
            const posts = await postsCollection.find({}).toArray();
            res.send(posts);
        });

        // CREATE POST
        app.post('/posts', verifyJWT, async (req, res) => {
            console.log('req.body', req.body)
            const newPost = req.body;

            const result = await postsCollection.insertOne(newPost);
            console.log('result', result)
            if(result.insertedCount > 0){
                res.send(result);
            }   
            // res.send(result);
        });

        // UPDATE POST
        app.put('/posts/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            const updatedPost = {
                title: req.body.title,
                content: req.body.content,
            };

            const result = await postsCollection.updateOne({_id: ObjectId(id)}, {$set: updatedPost});
            console.log('result', result)
            if(result.modifiedCount > 0){
                res.send(result);
            }
        });

        // DELETE POST
        app.delete('/posts/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            const result = await postsCollection.deleteOne({_id: ObjectId(id)});
            if(result.deletedCount > 0){
                res.send(result);
            }
        });

        // ADD LIKE
        app.put('/posts/:id/like', verifyJWT, async (req, res) => {
            const id = req.params.id;
            const post = await postsCollection.findOne({_id: ObjectId(id)});
            const likes = parseInt(post.likes);

            const updatedPost = {
                likes: likes + 1,
            };
            
            const result = await postsCollection.updateOne({_id: ObjectId(id)}, {$set: updatedPost}, {upsert: true});
            if(result.modifiedCount > 0){
                res.send(result);
            }
        });

        // ADD COMMENT
        app.put('/posts/:id/comment', verifyJWT, async (req, res) => {
            const id = req.params.id;

            const post = await postsCollection.findOne({_id: ObjectId(id)});
            const comments = post.comments;

            if(comments.length > 0){
                
            }

            const addedComment = {
                comments: req.body.comment,
            };

            const result = await postsCollection.updateOne({_id: ObjectId(id)}, {$push: addedComment}, {upsert: true});
            res.send(result);
        });
    }
    finally{

    }
}

run().catch(console.log);

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
    console.log(`Server running at port: ${port}`);
    }
);
