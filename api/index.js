const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const path = require("path");
const { MongoClient } = require("mongodb");

const app = express();

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB || "safe_redirector";

let clientPromise;

function getClient() {
  if (!MONGODB_URI) {
    throw new Error("MONGODB_URI is missing");
  }

  if (!clientPromise) {
    const client = new MongoClient(MONGODB_URI);
    clientPromise = client.connect();
  }

  return clientPromise;
}

async function getCollection() {
  const client = await getClient();
  const db = client.db(DB_NAME);
  const collection = db.collection("redirect_links");

  await collection.createIndex(
    { token: 1 },
    { unique: true }
  );

  return collection;
}

const ADMIN_KEY = process.env.ADMIN_KEY || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const BASE_URL = process.env.BASE_URL || "";

function generateToken() {
  return crypto.randomBytes(24).toString("base64url");
}

function createSignature(data) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(data)
    .digest("base64url");
}

function createSession(payload) {
  const body = Buffer
    .from(JSON.stringify(payload))
    .toString("base64url");

  const signature = createSignature(body);

  return `${body}.${signature}`;
}

function readSession(value) {
  try {
    if (!value || !value.includes(".")) {
      return null;
    }

    const [body, signature] = value.split(".");

    const expected = createSignature(body);

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (a.length !== b.length) {
      return null;
    }

    if (!crypto.timingSafeEqual(a, b)) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(body, "base64url").toString()
    );

    if (!payload.exp || payload.exp < Date.now()) {
      return null;
    }

    return payload;

  } catch {
    return null;
  }
}

function setSessionCookie(res, payload) {
  res.cookie(
    "rd",
    createSession(payload),
    {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 120000,
      path: "/"
    }
  );
}

function validateURL(value) {
  try {
    const url = new URL(String(value || ""));

    if (
      url.protocol !== "http:" &&
      url.protocol !== "https:"
    ) {
      return null;
    }

    return url.toString();

  } catch {
    return null;
  }
}

const generalLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 40,
  standardHeaders: true,
  legacyHeaders: false
});

const adminLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  express.json({
    limit: "20kb"
  })
);

app.use(cookieParser());

app.use(
  express.static(
    path.join(__dirname, "..", "public")
  )
);

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    database: "MongoDB"
  });
});

function isAdmin(req) {
  return (
    ADMIN_KEY &&
    req.get("x-admin-key") === ADMIN_KEY
  );
}


/*
|--------------------------------------------------------------------------
| CREATE REDIRECT LINK
|--------------------------------------------------------------------------
*/

app.post(
  "/api/admin/create",
  adminLimit,
  async (req, res) => {

    try {

      if (!isAdmin(req)) {
        return res.status(401).json({
          error: "Unauthorized"
        });
      }

      const destination = validateURL(
        req.body?.url
      );

      if (!destination) {
        return res.status(400).json({
          error: "Invalid URL"
        });
      }

      const collection = await getCollection();

      let token;

      while (true) {

        token = generateToken();

        const exists = await collection.findOne({
          token
        });

        if (!exists) {
          break;
        }
      }

      await collection.insertOne({
        token,
        destination,
        active: true,
        createdAt: new Date()
      });

      const base =
        BASE_URL ||
        `${req.protocol}://${req.get("host")}`;

      res.json({
        ok: true,
        token,
        url: `${base}/auto/${token}`
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Database error"
      });
    }
  }
);


/*
|--------------------------------------------------------------------------
| LIST LINKS
|--------------------------------------------------------------------------
*/

app.get(
  "/api/admin/list",
  adminLimit,
  async (req, res) => {

    try {

      if (!isAdmin(req)) {
        return res.status(401).json({
          error: "Unauthorized"
        });
      }

      const collection = await getCollection();

      const links = await collection
        .find({})
        .sort({
          createdAt: -1
        })
        .limit(100)
        .toArray();

      const base =
        BASE_URL ||
        `${req.protocol}://${req.get("host")}`;

      const result = links.map(link => ({
        token: link.token,
        destination: link.destination,
        active: link.active,
        createdAt: link.createdAt,
        shortUrl: `${base}/auto/${link.token}`
      }));

      res.json(result);

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Database error"
      });
    }
  }
);


/*
|--------------------------------------------------------------------------
| DISABLE LINK
|--------------------------------------------------------------------------
*/

app.post(
  "/api/admin/disable",
  adminLimit,
  async (req, res) => {

    try {

      if (!isAdmin(req)) {
        return res.status(401).json({
          error: "Unauthorized"
        });
      }

      const collection = await getCollection();

      const result =
        await collection.updateOne(
          {
            token: String(
              req.body?.token || ""
            )
          },
          {
            $set: {
              active: false
            }
          }
        );

      if (!result.matchedCount) {
        return res.status(404).json({
          error: "Token not found"
        });
      }

      res.json({
        ok: true
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Database error"
      });
    }
  }
);


/*
|--------------------------------------------------------------------------
| USER REDIRECT PAGE
|--------------------------------------------------------------------------
*/

app.get(
  "/auto/:token",
  generalLimit,
  async (req, res) => {

    try {

      const collection = await getCollection();

      const link =
        await collection.findOne({
          token: req.params.token
        });

      if (!link || !link.active) {

        return res
          .status(404)
          .sendFile(
            path.join(
              __dirname,
              "..",
              "public",
              "404.html"
            )
          );
      }

      const now = Date.now();

      setSessionCookie(res, {
        token: req.params.token,
        iat: now,
        readyAt: now + 3000,
        exp: now + 120000
      });

      res.sendFile(
        path.join(
          __dirname,
          "..",
          "public",
          "redirect.html"
        )
      );

    } catch (error) {

      console.error(error);

      res.status(500).send(
        "Database error"
      );
    }
  }
);


/*
|--------------------------------------------------------------------------
| COMPLETE REDIRECT
|--------------------------------------------------------------------------
*/

app.post(
  "/api/redirect/complete",
  generalLimit,
  async (req, res) => {

    try {

      const session =
        readSession(req.cookies.rd);

      if (!session) {

        return res.status(403).json({
          error: "Session expired"
        });
      }

      const collection =
        await getCollection();

      const link =
        await collection.findOne({
          token: session.token
        });

      if (!link || !link.active) {

        return res.status(404).json({
          error: "Link disabled"
        });
      }

      /*
       * Server-side 3 second protection.
       */

      if (Date.now() < session.readyAt) {

        const a =
          crypto.randomInt(2, 13);

        const b =
          crypto.randomInt(2, 13);

        setSessionCookie(res, {
          ...session,
          challenge: true,
          answer: a + b,
          challengeExp:
            Date.now() + 120000
        });

        return res.status(428).json({
          challenge: {
            question:
              `What is ${a} + ${b}?`
          }
        });
      }

      setSessionCookie(res, {
        token: session.token,
        verified: true,
        exp: Date.now() + 30000
      });

      res.json({
        ok: true,
        redirect: link.destination
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error: "Database error"
      });
    }
  }
);


/*
|--------------------------------------------------------------------------
| VERIFICATION CHALLENGE
|--------------------------------------------------------------------------
*/
module.exports = app;
