const express = require('express')
const app = express()
app.use(express.json())
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const path = require('path')

const dbPath = path.join(__dirname, 'twitterClone.db')
let db = null
const initializeDBandServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(3000, () => {
      console.log('the server is running..')
    })
  } catch (e) {
    console.log('error:', e)
    process.exit(-1)
  }
}
initializeDBandServer()

// MIDDLEWARE FUNCTION

const authenticateToken = async (request, response, next) => {
  let token
  const authHeader = request.headers['authorization']
  if (authHeader !== undefined) {
    token = authHeader.split(' ')[1]
  }
  if (token === undefined) {
    response.status(401).send('Invalid JWT Token')
  } else {
    jwt.verify(token, 'MY_SECRET_TOKEN', (error, payload) => {
      if (error) {
        response.status(401).send('Invalid JWT Token')
      } else {
        request.user = payload
        next()
      }
    })
  }
}

//USER REGISTRATION API

app.post('/register/', async (request, response) => {
  try {
    const {username, password, name, gender} = request.body

    // Check if the username already exists
    const dbQuery = 'SELECT * FROM user WHERE username = ?'
    const res = await db.get(dbQuery, [username])

    if (res === undefined) {
      // Check for password length
      if (password.length < 6) {
        response.status(400).send('Password is too short')
        return // Prevent further execution
      }

      // Hash password
      const hashedPass = await bcrypt.hash(password, 10)

      // Insert new user into the database
      const createUserQuery = `
        INSERT INTO user (username, password, name, gender) 
        VALUES (?, ?, ?, ?);`
      await db.run(createUserQuery, [username, hashedPass, name, gender])

      response.status(201).send('User created successfully')
    } else {
      response.status(400).send('User already exists')
    }
  } catch (error) {
    console.error('Error:', error)
    response.status(500).send('Internal Server Error')
  }
})

//USER LOGIN API
app.post('/login/', async (request, response) => {
  try {
    const {username, password} = request.body
    const query = `select * from user where  username = ?;`
    const user = await db.get(query, [username])
    if (user === undefined) {
      response.status(400).send('Invalid user')
    } else {
      const isPasswordMatched = await bcrypt.compare(password, user.password)
      if (!isPasswordMatched) {
        response.status(400).send('Invalid password')
      } else {
        const payload = {
          username: username,
        }
        const jwtToken = jwt.sign(payload, 'MY_SECRET_TOKEN')
        response.send({jwtToken})
      }
    }
  } catch (error) {
    console.error('Error:', error)
    response.status(500).send('Internal Server Error')
  }
})

//API3

app.get('/user/tweets/feed/', authenticateToken, async (request, response) => {
  try {
    const {username} = request.user

    const getUserIdQuery = `SELECT user_id FROM user WHERE username = ?`
    const user = await db.get(getUserIdQuery, [username])

    if (!user) {
      return response.status(400).send('Invalid user')
    }

    const userId = user.user_id

    const getFollowingUsersQuery = `
      SELECT following_user_id FROM follower WHERE follower_user_id = ?`

    const followingUsers = await db.all(getFollowingUsersQuery, [userId])

    if (followingUsers.length === 0) {
      return response.status(200).send([]) 
    }

    const followingUserIds = followingUsers.map(user => user.following_user_id)

    const getLatestTweetsQuery = `
      SELECT 
        user.username, 
        tweet.tweet, 
        tweet.date_time AS dateTime
      FROM tweet
      INNER JOIN user ON tweet.user_id = user.user_id
      WHERE tweet.user_id IN (${followingUserIds.map(() => '?').join(',')})
      ORDER BY tweet.date_time DESC
      LIMIT 4;`

    const latestTweets = await db.all(getLatestTweetsQuery, followingUserIds)

    response.status(200).send(latestTweets)
  } catch (error) {
    console.error('Error:', error)
    response.status(500).send('Internal Server Error')
  }
})

app.get('/user/following/', authenticateToken, async (request, response) => {
  try {
    const { username } = request.user;
    const userQuery = `SELECT user_id FROM user WHERE username = ?`;
    const user = await db.get(userQuery, [username]);

    const followingQuery = `
      SELECT user.name FROM user 
      INNER JOIN follower ON user.user_id = follower.following_user_id
      WHERE follower.follower_user_id = ?;`;

    const followingList = await db.all(followingQuery, [user.user_id]);

    response.status(200).send(followingList);
  } catch (error) {
    response.status(500).send('Internal Server Error');
  }
});

app.get('/user/followers/', authenticateToken, async (request, response) => {
  try {
    const { username } = request.user;
    const userQuery = `SELECT user_id FROM user WHERE username = ?`;
    const user = await db.get(userQuery, [username]);

    const followersQuery = `
      SELECT user.name FROM user 
      INNER JOIN follower ON user.user_id = follower.follower_user_id
      WHERE follower.following_user_id = ?;`;

    const followersList = await db.all(followersQuery, [user.user_id]);

    response.status(200).send(followersList);
  } catch (error) {
    response.status(500).send('Internal Server Error');
  }
});


app.get('/tweets/:tweetId/', authenticateToken, async (request, response) => {
  try {
    const { username } = request.user;
    const { tweetId } = request.params;

    const userQuery = `SELECT user_id FROM user WHERE username = ?`;
    const user = await db.get(userQuery, [username]);

    // Get users whom the logged-in user follows
    const followingQuery = `
      SELECT following_user_id FROM follower WHERE follower_user_id = ?`;
    const followingUsers = await db.all(followingQuery, [user.user_id]);
    const followingUserIds = followingUsers.map(user => user.following_user_id);

    // Get tweet details
    const tweetQuery = `
      SELECT tweet, user_id, date_time FROM tweet WHERE tweet_id = ?`;
    const tweet = await db.get(tweetQuery, [tweetId]);

    if (!tweet || !followingUserIds.includes(tweet.user_id)) {
      return response.status(401).send('Invalid Request');
    }

    // Get likes count
    const likesQuery = `SELECT COUNT(*) as likes FROM like WHERE tweet_id = ?`;
    const likes = await db.get(likesQuery, [tweetId]);

    // Get replies count
    const repliesQuery = `SELECT COUNT(*) as replies FROM reply WHERE tweet_id = ?`;
    const replies = await db.get(repliesQuery, [tweetId]);

    response.send({
      tweet: tweet.tweet,
      likes: likes.likes,
      replies: replies.replies,
      dateTime: tweet.date_time,
    });
  } catch (error) {
    response.status(500).send('Internal Server Error');
  }
});

app.get('/tweets/:tweetId/likes/', authenticateToken, async (request, response) => {
  try {
    const { username } = request.user;
    const { tweetId } = request.params;

    const userQuery = `SELECT user_id FROM user WHERE username = ?`;
    const user = await db.get(userQuery, [username]);

    const followingQuery = `
      SELECT following_user_id FROM follower WHERE follower_user_id = ?`;
    const followingUsers = await db.all(followingQuery, [user.user_id]);
    const followingUserIds = followingUsers.map(user => user.following_user_id);

    const tweetQuery = `SELECT user_id FROM tweet WHERE tweet_id = ?`;
    const tweet = await db.get(tweetQuery, [tweetId]);

    if (!tweet || !followingUserIds.includes(tweet.user_id)) {
      return response.status(401).send('Invalid Request');
    }

    const likesQuery = `
      SELECT user.username FROM user
      INNER JOIN like ON user.user_id = like.user_id
      WHERE like.tweet_id = ?;`;

    const likesList = await db.all(likesQuery, [tweetId]);
    response.send({ likes: likesList.map(user => user.username) });
  } catch (error) {
    response.status(500).send('Internal Server Error');
  }
});


app.get('/user/tweets/', authenticateToken, async (request, response) => {
  try {
    const { username } = request.user;
    const userQuery = `SELECT user_id FROM user WHERE username = ?`;
    const user = await db.get(userQuery, [username]);

    const tweetsQuery = `SELECT tweet, date_time FROM tweet WHERE user_id = ?`;
    const tweets = await db.all(tweetsQuery, [user.user_id]);

    response.send(tweets);
  } catch (error) {
    response.status(500).send('Internal Server Error');
  }
});


app.post('/user/tweets/', authenticateToken, async (request, response) => {
  try {
    const { username } = request.user;
    const { tweet } = request.body;
    
    const userQuery = `SELECT user_id FROM user WHERE username = ?`;
    const user = await db.get(userQuery, [username]);

    const createTweetQuery = `
      INSERT INTO tweet (tweet, user_id, date_time) VALUES (?, ?, datetime('now'))`;
    
    await db.run(createTweetQuery, [tweet, user.user_id]);

    response.send('Created a Tweet');
  } catch (error) {
    response.status(500).send('Internal Server Error');
  }
});


app.delete('/tweets/:tweetId/', authenticateToken, async (request, response) => {
  try {
    const { username } = request.user;
    const { tweetId } = request.params;

    const userQuery = `SELECT user_id FROM user WHERE username = ?`;
    const user = await db.get(userQuery, [username]);

    const tweetQuery = `SELECT user_id FROM tweet WHERE tweet_id = ?`;
    const tweet = await db.get(tweetQuery, [tweetId]);

    if (!tweet || tweet.user_id !== user.user_id) {
      return response.status(401).send('Invalid Request');
    }

    const deleteTweetQuery = `DELETE FROM tweet WHERE tweet_id = ?`;
    await db.run(deleteTweetQuery, [tweetId]);

    response.send('Tweet Removed');
  } catch (error) {
    response.status(500).send('Internal Server Error');
  }
});


module.exports = app;