package machine

// The bakery shop's code under /srv/bakery: a small Express + Postgres app,
// consistent with its package.json, .env, migrations and logs.

const bakeryServerTS = `import express from "express";
import helmet from "helmet";
import pino from "pino";
import pg from "pg";
import Stripe from "stripe";
import { z } from "zod";

const log = pino({}, pino.destination("/var/log/bakery/app.log"));
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 10 });
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "", { apiVersion: "2024-04-10" });

const app = express();
app.set("trust proxy", "loopback");
app.use(helmet());
app.use(express.json({ limit: "100kb" }));

app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    log.info(
      { reqId: req.get("x-request-id"), req: { method: req.method, url: req.originalUrl },
        res: { statusCode: res.statusCode }, responseTime: Date.now() - start },
      "request completed",
    );
  });
  next();
});

app.get("/api/products", async (_req, res) => {
  const { rows } = await pool.query(
    "SELECT id, slug, name, price_cents, in_stock FROM products WHERE active ORDER BY sort_order",
  );
  res.json(rows);
});

const Checkout = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(200),
  items: z.array(z.object({ productId: z.number().int(), qty: z.number().int().min(1).max(20) })).min(1),
});

app.post("/api/checkout", async (req, res) => {
  const parsed = Checkout.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid order" });
  const { email, name, items } = parsed.data;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const ids = items.map((i) => i.productId);
    const { rows: products } = await client.query(
      "SELECT id, price_cents FROM products WHERE id = ANY($1) AND active", [ids]);
    const total = items.reduce((sum, i) => {
      const p = products.find((p) => p.id === i.productId);
      return sum + (p ? p.price_cents * i.qty : 0);
    }, 0);
    const { rows: [customer] } = await client.query(
      "INSERT INTO customers (email, name, password_hash) VALUES ($1, $2, '') " +
        "ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name RETURNING id",
      [email, name]);
    const intent = await stripe.paymentIntents.create({ amount: total, currency: "eur", receipt_email: email });
    const { rows: [order] } = await client.query(
      "INSERT INTO orders (customer_id, total_cents, stripe_payment_intent) VALUES ($1, $2, $3) RETURNING id",
      [customer.id, total, intent.id]);
    await client.query("COMMIT");
    log.info({ orderId: order.id, totalCents: total }, "order paid");
    res.json({ orderId: order.id, clientSecret: intent.client_secret });
  } catch (err) {
    await client.query("ROLLBACK");
    log.error({ err }, "checkout failed");
    res.status(500).json({ error: "checkout failed" });
  } finally {
    client.release();
  }
});

app.use(express.static("dist/public", { maxAge: "1h" }));
app.get("*", (_req, res) => res.sendFile("index.html", { root: "dist/public" }));

const port = Number(process.env.PORT ?? 3000);
app.listen(port, "127.0.0.1", () => log.info({ port }, "bakery shop listening"));
`

const bakeryServerJS = `import express from "express";
import helmet from "helmet";
import pino from "pino";
import pg from "pg";
import Stripe from "stripe";
import { z } from "zod";
const log = pino({}, pino.destination("/var/log/bakery/app.log"));
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 10 });
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "", { apiVersion: "2024-04-10" });
const app = express();
app.set("trust proxy", "loopback");
app.use(helmet());
app.use(express.json({ limit: "100kb" }));
app.use((req, res, next) => {
    const start = Date.now();
    res.on("finish", () => {
        log.info({ reqId: req.get("x-request-id"), req: { method: req.method, url: req.originalUrl },
            res: { statusCode: res.statusCode }, responseTime: Date.now() - start }, "request completed");
    });
    next();
});
app.get("/api/products", async (_req, res) => {
    const { rows } = await pool.query("SELECT id, slug, name, price_cents, in_stock FROM products WHERE active ORDER BY sort_order");
    res.json(rows);
});
const Checkout = z.object({
    email: z.string().email(),
    name: z.string().min(1).max(200),
    items: z.array(z.object({ productId: z.number().int(), qty: z.number().int().min(1).max(20) })).min(1),
});
app.post("/api/checkout", async (req, res) => {
    const parsed = Checkout.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: "invalid order" });
    const { email, name, items } = parsed.data;
    const client = await pool.connect();
    try {
        await client.query("BEGIN");
        const ids = items.map((i) => i.productId);
        const { rows: products } = await client.query("SELECT id, price_cents FROM products WHERE id = ANY($1) AND active", [ids]);
        const total = items.reduce((sum, i) => {
            const p = products.find((p) => p.id === i.productId);
            return sum + (p ? p.price_cents * i.qty : 0);
        }, 0);
        const { rows: [customer] } = await client.query("INSERT INTO customers (email, name, password_hash) VALUES ($1, $2, '') " +
            "ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name RETURNING id", [email, name]);
        const intent = await stripe.paymentIntents.create({ amount: total, currency: "eur", receipt_email: email });
        const { rows: [order] } = await client.query("INSERT INTO orders (customer_id, total_cents, stripe_payment_intent) VALUES ($1, $2, $3) RETURNING id", [customer.id, total, intent.id]);
        await client.query("COMMIT");
        log.info({ orderId: order.id, totalCents: total }, "order paid");
        res.json({ orderId: order.id, clientSecret: intent.client_secret });
    }
    catch (err) {
        await client.query("ROLLBACK");
        log.error({ err }, "checkout failed");
        res.status(500).json({ error: "checkout failed" });
    }
    finally {
        client.release();
    }
});
app.use(express.static("dist/public", { maxAge: "1h" }));
app.get("*", (_req, res) => res.sendFile("index.html", { root: "dist/public" }));
const port = Number(process.env.PORT ?? 3000);
app.listen(port, "127.0.0.1", () => log.info({ port }, "bakery shop listening"));
//# sourceMappingURL=server.js.map
`

const bakeryLock = `{
  "name": "hazel-bakery-shop",
  "version": "2.4.1",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "hazel-bakery-shop",
      "version": "2.4.1",
      "dependencies": {
        "express": "^4.19.2",
        "helmet": "^7.1.0",
        "pg": "^8.11.5",
        "pino": "^9.1.0",
        "stripe": "^15.7.0",
        "zod": "^3.23.8"
      },
      "devDependencies": {
        "@types/express": "^4.17.21",
        "tsx": "^4.11.0",
        "typescript": "^5.4.5"
      }
    },
    "node_modules/express": {
      "version": "4.19.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.19.2.tgz",
      "license": "MIT",
      "engines": {
        "node": ">= 0.10.0"
      }
    },
    "node_modules/helmet": {
      "version": "7.1.0",
      "resolved": "https://registry.npmjs.org/helmet/-/helmet-7.1.0.tgz",
      "license": "MIT",
      "engines": {
        "node": ">=16.0.0"
      }
    },
    "node_modules/pg": {
      "version": "8.11.5",
      "resolved": "https://registry.npmjs.org/pg/-/pg-8.11.5.tgz",
      "license": "MIT",
      "engines": {
        "node": ">= 8.0.0"
      }
    },
    "node_modules/pino": {
      "version": "9.1.0",
      "resolved": "https://registry.npmjs.org/pino/-/pino-9.1.0.tgz",
      "license": "MIT",
      "bin": {
        "pino": "bin.js"
      }
    },
    "node_modules/stripe": {
      "version": "15.7.0",
      "resolved": "https://registry.npmjs.org/stripe/-/stripe-15.7.0.tgz",
      "license": "MIT",
      "engines": {
        "node": ">=12.*"
      }
    },
    "node_modules/typescript": {
      "version": "5.4.5",
      "resolved": "https://registry.npmjs.org/typescript/-/typescript-5.4.5.tgz",
      "dev": true,
      "license": "Apache-2.0",
      "bin": {
        "tsc": "bin/tsc",
        "tsserver": "bin/tsserver"
      },
      "engines": {
        "node": ">=14.17"
      }
    },
    "node_modules/zod": {
      "version": "3.23.8",
      "resolved": "https://registry.npmjs.org/zod/-/zod-3.23.8.tgz",
      "license": "MIT"
    }
  }
}
`
