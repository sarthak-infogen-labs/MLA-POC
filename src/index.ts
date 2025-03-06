import express, { Request, Response } from "express";
import axios from "axios";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import session from "express-session";

dotenv.config();
const app = express();
app.use(cors());

// Use session middleware to store the code verifier
app.use(
  session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: true,
  })
);

const PORT = 3000;

// Function to generate a random code verifier
const generateCodeVerifier = (): string => {
  return crypto.randomBytes(32).toString("base64url");
};

// Function to generate a SHA256-based code challenge
const generateCodeChallenge = (codeVerifier: string): string => {
  return crypto.createHash("sha256").update(codeVerifier).digest("base64url");
};

// Step 1: Redirect user to Salesforce login with PKCE
app.get("/auth/salesforce", (req: Request, res: Response) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  // Store the code verifier in the session
  (req.session as any).codeVerifier = codeVerifier;

  const authUrl = `${process.env.SALESFORCE_AUTH_URL}?response_type=code&client_id=${process.env.SALESFORCE_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.SALESFORCE_REDIRECT_URI as string)}&code_challenge=${codeChallenge}&code_challenge_method=S256`;

  console.log("Redirecting to:", authUrl);
  res.redirect(authUrl);
});

// Step 2: Handle OAuth Callback and Exchange Code for Token
app.get("/auth/callback", async (req: Request, res: Response) => {
  console.log("Query params received:", req.query);
  const code = req.query.code as string;
  if (!code) {
    console.error("Authorization code missing");
     res.status(400).send("Authorization code missing");
     return;
  }

  // Retrieve the stored code_verifier from session
  const codeVerifier = (req.session as any)?.codeVerifier;
  if (!codeVerifier) {
    console.error("Missing code_verifier in session");
     res.status(400).send("PKCE verification failed");
     return;
  }

  try {
    const tokenResponse = await axios.post(process.env.SALESFORCE_TOKEN_URL as string, null, {
      params: {
        grant_type: "authorization_code",
        client_id: process.env.SALESFORCE_CLIENT_ID,
        client_secret: process.env.SALESFORCE_CLIENT_SECRET,
        redirect_uri: process.env.SALESFORCE_REDIRECT_URI,
        code,
        code_verifier: codeVerifier, // Send the code_verifier
      },
    });

    const { access_token, instance_url } = tokenResponse.data;

    console.log(access_token)
    // Fetch User Info
    const userInfoResponse = await axios.get(`${instance_url}/services/oauth2/userinfo`, {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    console.log(userInfoResponse)

    res.json({ user: userInfoResponse.data, access_token });
  } catch (error: any) {
    console.error("Error exchanging code for token:", error.response?.data || error.message);
    res.status(500).send("Authentication failed");
  }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
