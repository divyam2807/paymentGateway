// server.js
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');

const app = express();

// Capture raw body for webhook signature verification while still parsing JSON
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// CORS: allow only your frontend origin in production (use env var)
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-razorpay-signature');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const RAZOR_KEY_ID = process.env.RAZOR_KEY_ID;
const RAZOR_KEY_SECRET = process.env.RAZOR_KEY_SECRET;
if (!RAZOR_KEY_ID || !RAZOR_KEY_SECRET) {
  console.error('Missing RAZOR_KEY_ID or RAZOR_KEY_SECRET in environment. Exiting.');
  process.exit(1);
}

function razorAuthHeader() {
  return 'Basic ' + Buffer.from(`${RAZOR_KEY_ID}:${RAZOR_KEY_SECRET}`).toString('base64');
}

// Health
app.get('/', (req, res) => res.send('Payment backend running'));

// Create a Razorpay Payment Link
// POST /api/create-link  { amount_in_inr: number }
app.post('/api/create-link', async (req, res) => {
  try {
    const { amount_in_inr } = req.body;
    if (!amount_in_inr || typeof amount_in_inr !== 'number') {
      return res.status(400).json({ error: 'amount_in_inr required (number)' });
    }
    const amountPaise = Math.round(amount_in_inr * 100);

    const payload = {
      amount: amountPaise,
      currency: "INR",
      accept_partial: false,
      description: "Payment to me (demo)"
      // optional: customer: { name, contact, email }
      // optional: expires_at, notify, reference_id, etc.
    };

    const resp = await fetch('https://api.razorpay.com/v1/payment_links', {
      method: 'POST',
      headers: {
        'Authorization': razorAuthHeader(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const data = await resp.json();
    if (!resp.ok) {
      console.error('Razorpay create-link error:', data);
      return res.status(502).json({ error: 'payment provider error', details: data });
    }

    // Return the hosted link for frontend to redirect user to
    return res.json({ link_url: data.short_url || data.link_url });
  } catch (err) {
    console.error('create-link error:', err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

// Webhook receiver
// POST /api/webhook  (Razorpay will POST events here)
app.post('/api/webhook', (req, res) => {
  const webhookSecret = process.env.RAZOR_WEBHOOK_SECRET;
  if (!webhookSecret) {
    console.warn('RAZOR_WEBHOOK_SECRET not configured');
    return res.status(500).send('webhook secret not configured');
  }

  const signature = req.headers['x-razorpay-signature'];
  const raw = req.rawBody;
  if (!signature || !raw) {
    console.warn('Missing signature or raw body');
    return res.status(400).send('bad request');
  }

  const expected = crypto.createHmac('sha256', webhookSecret).update(raw).digest('hex');

  if (signature === expected) {
    // Valid webhook
    const event = req.body.event;
    console.log('Verified webhook event:', event);
    // Example: handle payment_link.paid
    if (event === 'payment_link.paid') {
      // Details are in req.body.payload.payment.entity or req.body.payload.payment_link
      console.log('Payment link paid payload:', JSON.stringify(req.body.payload || req.body).slice(0, 1000));
      // TODO: mark order as paid in DB / send notification
    }
    return res.status(200).send('ok');
  } else {
    console.warn('Invalid webhook signature');
    return res.status(400).send('invalid signature');
  }
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
