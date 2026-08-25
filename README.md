# Safe Redirector — GitHub + Vercel + PostgreSQL

1. Upload this folder to GitHub. Do NOT upload `.env`.
2. Create a PostgreSQL database (Neon/Supabase/etc.) and copy its connection string.
3. Import the GitHub repo into Vercel.
4. Add Vercel Environment Variables:
   - DATABASE_URL
   - ADMIN_KEY
   - SESSION_SECRET
   - BASE_URL = your Vercel URL
5. Redeploy.
6. Open `/admin.html`, enter ADMIN_KEY, paste a URL, and Generate Link.
7. Users open `/auto/TOKEN`.

The database table is created automatically. The destination is stored server-side and is returned only after the server-enforced 3-second check. The math challenge is a lightweight verification step, not a full CAPTCHA. For stronger bot protection, integrate Cloudflare Turnstile and verify it server-side.
