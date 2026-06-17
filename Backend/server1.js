const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const crypto = require('crypto'); // Built-in Node.js cryptographic module

const app = express();
app.use(express.json());
app.use(cors());

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: '_iot_db',
  password: 'astro-cod3x', // Use your pgAdmin credential password here
  port: 5432,
});

// HIGH EFFICIENCY DATA RECEIVER ENDPOINT
app.post('/api/v1/data', async (req, res) => {
  const { device_id, token, ...payload } = req.body;
  if (!device_id || !token) {
    return res.status(400).json({ error: "Missing identity credentials." });
  }

  try {
    // 1. Secure Crypto Gateway: Hash the incoming string token instantly using SHA-256
    const calculatedHash = crypto.createHash('sha256').update(token).digest('hex');
//-- Visual Diagnostic Step: Print calculated hash string length and content
    console.log(`[CRYPTO] Length: ${calculatedHash.length} | Hash: ${calculatedHash}`);
    // Check hash against the secured database records
    const deviceVerify = await pool.query(
      'SELECT is_active FROM devices WHERE device_id = $1 AND api_token_hash = $2',
      [device_id, calculatedHash]
    );

    if (deviceVerify.rows.length === 0 || !deviceVerify.rows[0].is_active) {
      return res.status(401).json({ error: "Authentication Failed: Node unauthorized." });
    }

    // 2. High Performance Parsing: Deconstruct dynamic payload rows efficiently
    const insertQuery = `
      INSERT INTO iot_data_stream (device_id, metric_name, numeric_value, text_value, boolean_value)
      VALUES ($1, $2, $3, $4, $5)
    `;

    // Loop through any arbitrary payload variables sent by users without using slow JSON text lookups
    for (const [metricName, value] of Object.entries(payload)) {
      let numericVal = null, textVal = null, booleanVal = null;

      if (typeof value === 'number') numericVal = value;
      else if (typeof value === 'boolean') booleanVal = value;
      else textVal = String(value);

      // Execute optimized parametric database inserts independently
      await pool.query(insertQuery, [device_id, metricName, numericVal, textVal, booleanVal]);
    }

    res.status(200).json({ status: "Success", messages_logged: Object.keys(payload).length });

  } catch (err) {
    console.error("Ingestion fault:", err.message);
    res.status(500).send("Database node structural failure.");
  }
});

// UPGRADED COMPACT FETCH ENDPOINT FOR LIVE VIEW PANELS
app.get('/api/v1/data/:device_id', async (req, res) => {
  try {
    // Fetches the most recent update for every distinct variable name via our tracking indexes
    const queryStr = `
      SELECT DISTINCT ON (metric_name) metric_name, numeric_value, text_value, boolean_value, timestamp
      FROM iot_data_stream
      WHERE device_id = $1
      ORDER BY metric_name, timestamp DESC;
    `;
    const result = await pool.query(queryStr, [req.params.device_id]);
    
    // Structure row properties neatly back into an easy-to-read JSON snapshot layout for the frontend dashboard
    const structuredPayload = {};
    result.rows.forEach(row => {
        if (row.numeric_value !== null) structuredPayload[row.metric_name] = Number(row.numeric_value);
        else if (row.boolean_value !== null) structuredPayload[row.metric_name] = row.boolean_value;
        else structuredPayload[row.metric_name] = row.text_value;
    });

    res.json({ device_id: req.params.device_id, metrics: structuredPayload });
  } catch (err) {
    res.status(500).json({ error: "Read transaction query failed." });
  }
});

const PORT = 3000;
app.listen(PORT, () => console.log(`🚀 Secure Ingestion Engine running locally on port ${PORT}`));