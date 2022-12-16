const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const port = 5000 || process.env.PORT;

const app = express();
require('dotenv').config();
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.nvyyp05.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true, serverApi: ServerApiVersion.v1 });

// Verify Token
function verifyJWT(req, res, next){
    const authHeader = req.headers.authorization;
    if(!authHeader){
        res.status(401).send('Unauthorized access');
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if(err){
            res.status(403).send('Forbidden access');
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
            res.send('User has been created');
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

        // FORGOT PASSWORD
        app.post('/forgot-password', async (req, res) => {
            const email = req.body.email;
            const user = await usersCollection.findOne({
                email: email
            });
            if(user == null){
                res.status(400).send('User does not exist');
            }
            else{
                const token = jwt.sign({email}, process.env.RESET_TOKEN_SECRET, {expiresIn: '20m'});
                res.send({resetToken: token});
            }
        });

        // RESET PASSWORD
        app.post('/reset-password', async (req, res) => {
            const token = req.headers.token;
            const password = req.body.newPassword;
            const hashedPassword = await bcrypt.hash(password, 10);

            if(token == null){
                res.status(401).send('Unauthorized access');
            }

            jwt.verify(token, process.env.RESET_TOKEN_SECRET, async (err, decoded) => {
                if(err){
                    res.status(403).send('Forbidden access');
                }
                const email = decoded.email;
                const result = await usersCollection.updateOne({email: email}, {$set: {password: hashedPassword}});
                res.send('Password has been reset');
            });
        });


        // GET POSTS
        app.get('/posts', async (req, res) => {
            const postsCollection = client.db("atgTask2").collection("posts");
            const posts = await postsCollection.find({}).toArray();
            res.send(posts);
        });

        // CREATE POST
        app.post('/posts', verifyJWT, async (req, res) => {
            const newPost = req.body;

            const result = await postsCollection.insertOne(newPost);
            res.send('Post has been created');
        });

        // UPDATE POST
        app.put('/posts/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            const updatedPost = {
                title: req.body.title,
                content: req.body.content,
            };

            const result = await postsCollection.updateOne({_id: ObjectId(id)}, {$set: updatedPost});
            res.send('Post has been updated');
        });

        // DELETE POST
        app.delete('/posts/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            const result = await postsCollection.deleteOne({_id: ObjectId(id)});
            res.send('Post has been deleted');
        });

        // ADD LIKE
        app.put('/posts/like/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            const post = await postsCollection.findOne({_id: ObjectId(id)});
            const likes = parseInt(post.likes);
            if(!likes){
                updatedPost = {
                    likes: 1,
                };    
            } else{
                updatedPost = {
                    likes: likes + 1,
                };
            }

            const result = await postsCollection.updateOne({_id: ObjectId(id)}, {$set: updatedPost}, {upsert: true});
            res.send('Post has been liked');
        });

        // ADD COMMENT
        app.put('/posts/comment/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;

            const post = await postsCollection.findOne({_id: ObjectId(id)});
            const comments = post.comments;

            if(!comments){
                updatedPost = {
                    comments: [req.body.comment],
                };
            } else{
                updatedPost = {
                    comments: [...comments, req.body.comment],
                };
            }

            const result = await postsCollection.updateOne({_id: ObjectId(id)}, {$set: updatedPost}, {upsert: true});
            res.send('Comment has been added');
        });
    }
    catch(err){
        console.log(err);
    }
}

run().catch(console.log);

app.get('/', (req, res) => {
  res.send('Server is up');
});

app.listen(port, () => {
    console.log(`Server running at port: ${port}`);
    }
);
