require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const bodyParser = require('body-parser');
const { google } = require('googleapis');
const cookieParser = require('cookie-parser');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const fs = require('fs');

// Firebase Admin Initialization
const firebaseBase64 = process.env.FIREBASE_KEY_BASE64;
const firebasePath = path.join(__dirname, 'firebase-key.json');

if (firebaseBase64 && !fs.existsSync(firebasePath)) {
  fs.writeFileSync(firebasePath, Buffer.from(firebaseBase64, 'base64').toString('utf-8'));
}

const serviceAccount = require('./firebase-key.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();

// Express Setup
const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());

// Passport Google OAuth Setup
passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_OAUTH_CALLBACK_URL || "http://localhost:3001/auth/google/callback",
    },
    function (accessToken, refreshToken, profile, done) {
      // Restrict access to only your Gmail
      const allowedEmail = 'hamzabsarfraz@gmail.com';
      const userEmail = profile.emails[0].value;
      if (userEmail === allowedEmail) {
        return done(null, profile);
      } else {
        return done(null, false, { message: 'Unauthorized email address' });
      }
    }
  )
);

// Auth Routes
app.get('/login', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/access-denied' }),
  (req, res) => {
    res.redirect(process.env.POST_AUTH_REDIRECT || '/admin-preview');
  }
);
app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/login');
  });
});

// Access Denied page
app.get('/access-denied', (req, res) => {
  res.status(403).send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Access Denied</title>
      <style>
        body {
          min-height: 100vh;
          margin: 0;
          padding: 0;
          font-family: 'Poppins', 'Segoe UI', Arial, sans-serif;
          background: linear-gradient(135deg, #f5f7fa 0%, #e9f3ee 100%);
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .denied-container {
          background: #fff;
          border-radius: 20px;
          box-shadow: 0 8px 32px rgba(167,32,51,0.12);
          border: 1px solid #f5c6cb;
          max-width: 520px;
          width: 100%;
          padding: 2.5rem 2rem;
          text-align: center;
        }
        .denied-icon {
          width: 64px;
          height: 64px;
          background: #f8d7da;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          margin: 0 auto 1.2rem;
        }
        .denied-icon svg {
          width: 32px;
          height: 32px;
          color: #a72033;
        }
        h2 {
          color: #a72033;
          font-size: 1.3rem;
          margin-bottom: 1.2rem;
          white-space: nowrap;
        }
        .denied-message {
          color: #a72033;
          font-size: 1.02rem;
          margin-bottom: 0.7rem;
          white-space: nowrap;
        }
        .try-again-btn {
          background: linear-gradient(45deg, #01411C, #026C2E, #01411C);
          background-size: 300% 300%;
          color: white;
          padding: 12px 28px;
          border: none;
          border-radius: 12px;
          font-size: 1rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
          box-shadow: 0 2px 8px rgba(1, 65, 28, 0.13);
          text-decoration: none;
          display: inline-block;
          margin-top: 1.2rem;
        }
        .try-again-btn:hover {
          filter: brightness(1.08);
          transform: translateY(-2px);
          box-shadow: 0 4px 16px rgba(1, 65, 28, 0.18);
        }
      </style>
    </head>
    <body>
      <div class="denied-container">
        <div class="denied-icon">
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </div>
        <h2>Access Denied</h2>
        <div class="denied-message">You are not authorized to access the admin preview.</div>
        <div class="denied-message">Please sign in with the correct Google account.</div>
        <a href="/login" class="try-again-btn">Try Again</a>
      </div>
    </body>
    </html>
  `);
});

// Middleware to protect admin-preview
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

// Google Calendar Setup
const googleCalendarBase64 = process.env.GOOGLE_CALENDAR_KEY_BASE64;
const googleCalendarPath = path.join(__dirname, 'google-calendar-key.json');

if (googleCalendarBase64 && !fs.existsSync(googleCalendarPath)) {
  fs.writeFileSync(googleCalendarPath, Buffer.from(googleCalendarBase64, 'base64').toString('utf-8'));
}

const SCOPES = ['https://www.googleapis.com/auth/calendar'];
const auth = new google.auth.GoogleAuth({
  keyFile: './google-calendar-key.json',
  scopes: SCOPES,
});
const calendar = google.calendar('v3');

// Submit Birthday (Public Form)
app.post('/submit', async (req, res) => {
  try {
    const { name, birthday, relationship } = req.body;

    if (!name || !birthday) {
      return res.status(400).json({ error: 'Name and birthday are required' });
    }

    const docRef = await db.collection('birthdays').add({
      name,
      birthday,
      relationship: relationship || '',
      status: 'pending',
      submittedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.status(201).send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Birthday Submitted</title>
        <style>
          body {
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            font-family: 'Poppins', 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #e9f3ee 100%);
            display: flex;
            align-items: center;
            justify-content: center;
          }
          .confirmation-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 8px 32px rgba(1, 65, 28, 0.12);
            border: 1px solid rgba(1, 65, 28, 0.18);
            max-width: 500px;
            width: 100%;
            padding: 2.5rem;
            text-align: center;
          }
          .success-icon {
            width: 80px;
            height: 80px;
            background: #e6f4ec;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1.5rem;
          }
          .success-icon svg {
            width: 40px;
            height: 40px;
            color: #026C2E;
          }
          h2 {
            color: #01411C;
            font-size: 1.8rem;
            margin-bottom: 1rem;
          }
          .message {
            color: #026C2E;
            font-size: 1.1rem;
            margin-bottom: 2rem;
            line-height: 1.5;
          }
          .btn {
            background: linear-gradient(45deg, #01411C, #026C2E, #01411C);
            background-size: 300% 300%;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(1, 65, 28, 0.13);
            text-decoration: none;
            display: inline-block;
            min-width: 200px;
          }
          .btn:hover {
            filter: brightness(1.08);
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(1, 65, 28, 0.18);
          }
        </style>
      </head>
      <body>
        <div class="confirmation-container">
          <div class="success-icon">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h2>Birthday Submitted!</h2>
          <p class="message">
            Thank you for submitting ${name}'s birthday.<br>
            It will be reviewed and added to the calendar soon.
          </p>
          <a href="/" class="btn">Submit Another Birthday</a>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Error submitting birthday:', error);
    res.status(500).json({ error: 'Failed to submit birthday' });
  }
});

// Get All Birthdays (Admin Preview)
app.get('/birthdays', async (req, res) => {
  try {
    const snapshot = await db.collection('birthdays').orderBy('submittedAt', 'desc').get();
    const birthdays = [];
    snapshot.forEach((doc) => {
      birthdays.push({ id: doc.id, ...doc.data() });
    });
    res.json(birthdays);
  } catch (error) {
    console.error('Error fetching birthdays:', error);
    res.status(500).json({ error: 'Failed to fetch birthdays' });
  }
});

// Approve Birthday + Add to Google Calendar
app.post('/approve/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const docRef = db.collection('birthdays').doc(id);
    const doc = await docRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'Birthday not found' });
    }

    const data = doc.data();
    const birthdayDate = new Date(data.birthday);
    const currentYear = new Date().getFullYear();
    const age = currentYear - birthdayDate.getFullYear();

    const event = {
      summary: `🎂 ${data.name}'s Birthday`,
      description: `${
        data.relationship ? `Relationship: ${data.relationship}\n` : ''
      }Turning ${age} this year 🎉`,
      start: { date: data.birthday },
      end: { date: data.birthday },
      recurrence: ['RRULE:FREQ=YEARLY'],
    };

    const authClient = await auth.getClient();
    await calendar.events.insert({
      auth: authClient,
      calendarId: 'hamzabsarfraz@gmail.com',
      resource: event,
    });

    await docRef.update({
      status: 'approved',
      approvedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ message: '🎉 Birthday approved and added to calendar' });
  } catch (error) {
    console.error('❌ Google API error:', error);
    res.status(500).json({ error: 'Failed to add to calendar' });
  }
});

// Decline Birthday
app.post('/decline/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const docRef = db.collection('birthdays').doc(id);
    const doc = await docRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'Birthday not found' });
    }

    await docRef.update({
      status: 'declined',
      declinedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ message: 'Birthday declined' });
  } catch (error) {
    console.error('Error declining birthday:', error);
    res.status(500).json({ error: 'Failed to decline birthday' });
  }
});

// GET /approve/:id - Approve and add to Google Calendar (for direct link clicks)
app.get('/approve/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const docRef = db.collection('birthdays').doc(id);
    const doc = await docRef.get();

    if (!doc.exists) {
      return res.status(404).send('Birthday not found.');
    }

    const data = doc.data();
    const birthdayDate = new Date(data.birthday);
    const currentYear = new Date().getFullYear();
    const age = currentYear - birthdayDate.getFullYear();

    const event = {
      summary: `🎂 ${data.name}'s Birthday`,
      description: `${data.relationship ? `Relationship: ${data.relationship}\n` : ''}Turning ${age} this year 🎉`,
      start: {
        date: data.birthday,
      },
      end: {
        date: data.birthday,
      },
      recurrence: ['RRULE:FREQ=YEARLY'],
    };

    const authClient = await auth.getClient();
    await calendar.events.insert({
      auth: authClient,
      calendarId: 'hamzabsarfraz@gmail.com',
      resource: event,
    });

    await docRef.update({
      status: 'approved',
      approvedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Birthday Approved</title>
        <style>
          body {
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            font-family: 'Poppins', 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(to bottom, #d6f0ff 0%, #e6f4ec 80%, #ffffff 100%);
            display: flex;
            align-items: center;
            justify-content: center;
          }
          .confirmation-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 8px 32px rgba(1, 65, 28, 0.12);
            border: 1px solid rgba(1, 65, 28, 0.18);
            max-width: 500px;
            width: 100%;
            padding: 2.5rem;
            text-align: center;
          }
          .success-icon {
            width: 80px;
            height: 80px;
            background: #e6f4ec;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1.5rem;
          }
          .success-icon svg {
            width: 40px;
            height: 40px;
            color: #026C2E;
          }
          h2 {
            color: #01411C;
            font-size: 1.8rem;
            margin-bottom: 1rem;
          }
          .message {
            color: #026C2E;
            font-size: 1.1rem;
            margin-bottom: 2rem;
            line-height: 1.5;
          }
          .back-btn {
            background: linear-gradient(45deg, #01411C, #026C2E, #01411C);
            background-size: 300% 300%;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(1, 65, 28, 0.13);
            text-decoration: none;
            display: inline-block;
          }
          .back-btn:hover {
            filter: brightness(1.08);
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(1, 65, 28, 0.18);
          }
        </style>
      </head>
      <body>
        <div class="confirmation-container">
          <div class="success-icon">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <h2>Birthday Approved!</h2>
          <p class="message">
            ${data.name}'s birthday has been added to your Google Calendar.<br>
            You'll be reminded every year on ${data.birthday}.
          </p>
          <a href="/admin-preview" class="back-btn">Back to Admin Preview</a>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    console.error('❌ Approval error (GET):', err);
    res.status(500).send("Something went wrong.");
  }
});

// GET /decline/:id - Decline a birthday submission (for direct link clicks)
app.get('/decline/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const docRef = db.collection('birthdays').doc(id);
    const doc = await docRef.get();

    if (!doc.exists) {
      return res.status(404).send('Birthday not found.');
    }

    await docRef.update({
      status: 'declined',
      declinedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Birthday Declined</title>
        <style>
          body {
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            font-family: 'Poppins', 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(to bottom, #d6f0ff 0%, #e6f4ec 80%, #ffffff 100%);
            display: flex;
            align-items: center;
            justify-content: center;
          }
          .confirmation-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 8px 32px rgba(1, 65, 28, 0.12);
            border: 1px solid rgba(1, 65, 28, 0.18);
            max-width: 500px;
            width: 100%;
            padding: 2.5rem;
            text-align: center;
          }
          .decline-icon {
            width: 80px;
            height: 80px;
            background: #fef2f2;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1.5rem;
          }
          .decline-icon svg {
            width: 40px;
            height: 40px;
            color: #dc2626;
          }
          h2 {
            color: #01411C;
            font-size: 1.8rem;
            margin-bottom: 1rem;
          }
          .message {
            color: #666;
            font-size: 1.1rem;
            margin-bottom: 2rem;
            line-height: 1.5;
          }
          .back-btn {
            background: linear-gradient(45deg, #01411C, #026C2E, #01411C);
            background-size: 300% 300%;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(1, 65, 28, 0.13);
            text-decoration: none;
            display: inline-block;
          }
          .back-btn:hover {
            filter: brightness(1.08);
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(1, 65, 28, 0.18);
          }
        </style>
      </head>
      <body>
        <div class="confirmation-container">
          <div class="decline-icon">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </div>
          <h2>Birthday Declined</h2>
          <p class="message">
            The birthday submission has been declined.<br>
            You can always review declined submissions in the admin preview.
          </p>
          <a href="/admin-preview" class="back-btn">Back to Admin Preview</a>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    console.error('❌ Decline error (GET):', err);
    res.status(500).send("Something went wrong.");
  }
});

// Admin Preview (HTML)
app.get('/admin-preview', ensureAuthenticated, async (req, res) => {
  try {
    const snapshot = await db.collection('birthdays').orderBy('submittedAt', 'desc').get();
    let html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Hamza's Family Calendar - Admin Preview</title>
        <style>
          body {
            min-height: 100vh;
            margin: 0;
            padding: 0;
            font-family: 'Poppins', 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(to bottom, #d6f0ff 0%, #e6f4ec 80%, #ffffff 100%);
            display: flex;
            align-items: flex-start;
            justify-content: center;
          }
          .admin-container {
            margin: 40px 0;
            background: rgba(255,255,255,0.97);
            border-radius: 20px;
            box-shadow: 0 8px 32px rgba(1, 65, 28, 0.12);
            border: 1px solid rgba(1, 65, 28, 0.18);
            max-width: 1000px;
            width: 100%;
            padding: 2.5rem 2rem;
            position: relative;
          }
          .logout-btn {
            position: absolute;
            top: 24px;
            right: 32px;
            background: linear-gradient(45deg, #a72033, #c0392b, #a72033);
            background-size: 300% 300%;
            color: white;
            padding: 10px 22px;
            border: none;
            border-radius: 10px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            box-shadow: 0 2px 8px rgba(167,32,51,0.13);
            text-decoration: none;
            z-index: 10;
          }
          .logout-btn:hover {
            filter: brightness(1.08);
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(167,32,51,0.18);
          }
          h1 {
            color: #01411C;
            text-align: center;
            font-size: 2rem;
            margin-bottom: 2rem;
            font-family: 'Poppins', sans-serif;
            letter-spacing: 1px;
          }
          .birthday-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
          }
          .birthday-card {
            background: #fff;
            border-radius: 16px;
            box-shadow: 0 2px 8px rgba(1, 65, 28, 0.07);
            padding: 1.2rem;
            display: flex;
            align-items: center;
            gap: 1.5rem;
            border: 1px solid #e6f4ec;
          }
          .birthday-info {
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 0.3rem;
          }
          .name {
            font-size: 1.15rem;
            font-weight: 600;
            color: #01411C;
          }
          .details {
            display: flex;
            gap: 1.5rem;
            color: #026C2E;
            font-size: 0.95rem;
          }
          .detail-item {
            display: flex;
            align-items: center;
            gap: 0.4rem;
          }
          .status-section {
            display: flex;
            align-items: center;
            gap: 1rem;
            min-width: 280px;
          }
          .status-badge {
            display: inline-block;
            padding: 0.25em 0.8em;
            border-radius: 12px;
            font-size: 0.95em;
            font-weight: 500;
            white-space: nowrap;
          }
          .status-badge.pending {
            background: #fffbe6;
            color: #bfa100;
            border: 1px solid #ffe066;
          }
          .status-badge.approved {
            background: #e6f4ec;
            color: #026C2E;
            border: 1px solid #b7e4c7;
          }
          .status-badge.declined {
            background: #f8d7da;
            color: #a72033;
            border: 1px solid #f5c6cb;
          }
          .actions {
            display: flex;
            gap: 0.7rem;
          }
          .action-btn {
            background: linear-gradient(45deg, #01411C, #026C2E, #01411C);
            background-size: 300% 300%;
            color: white;
            padding: 8px 16px;
            border: none;
            border-radius: 8px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(1, 65, 28, 0.13);
            text-shadow: 1px 1px 2px rgba(0,0,0,0.07);
            white-space: nowrap;
          }
          .action-btn.decline {
            background: linear-gradient(45deg, #a72033, #c0392b, #a72033);
            background-size: 300% 300%;
          }
          .action-btn:hover {
            filter: brightness(1.08);
            transform: translateY(-1px);
            box-shadow: 0 4px 16px rgba(1, 65, 28, 0.18);
          }
          @media (max-width: 900px) {
            .birthday-card {
              flex-direction: column;
              align-items: flex-start;
              gap: 1rem;
            }
            .status-section {
              width: 100%;
              justify-content: space-between;
            }
            .details {
              flex-direction: column;
              gap: 0.5rem;
            }
          }
          @media (max-width: 700px) {
            .admin-container {
              padding: 1.2rem 0.5rem;
            }
            .birthday-card {
              padding: 1rem;
            }
            .status-section {
              flex-direction: column;
              align-items: flex-start;
              gap: 0.8rem;
            }
            .actions {
              width: 100%;
            }
            .action-btn {
              flex: 1;
            }
          }
        </style>
      </head>
      <body>
        <div class="admin-container">
          <a href="/logout" class="logout-btn">Logout</a>
          <h1>Hamza's Family Calendar<br><span style="font-size:1.1rem;font-weight:400;">Admin Preview</span></h1>
          <div class="birthday-list">
    `;

    if (snapshot.empty) {
      html += '<p style="text-align:center;color:#01411C;">No birthday submissions yet.</p>';
    } else {
      snapshot.forEach(doc => {
        const data = doc.data();
        html += `
          <div class="birthday-card">
            <div class="birthday-info">
              <div class="name">${data.name}</div>
              <div class="details">
                <div class="detail-item">
                  <span>👤</span>
                  <span>${data.relationship || 'No relationship specified'}</span>
                </div>
                <div class="detail-item">
                  <span>🎂</span>
                  <span>${data.birthday}</span>
                </div>
              </div>
            </div>
            <div class="status-section">
              <div class="status-badge ${data.status}">${data.status.charAt(0).toUpperCase() + data.status.slice(1)}</div>
              ${data.status === 'pending' ? `
                <div class="actions">
                  <button class="action-btn" onclick="window.location.href='/approve/${doc.id}'">Approve</button>
                  <button class="action-btn decline" onclick="window.location.href='/decline/${doc.id}'">Decline</button>
                </div>
              ` : ''}
            </div>
          </div>
        `;
      });
    }

    html += `
          </div>
        </div>
      </body>
      </html>
    `;

    res.send(html);
  } catch (error) {
    res.status(500).send('Something went wrong');
  }
});

// Start Server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 