# StreamTV ⚽

A dark, mobile-first football channel hub with neon-green accents.

## Included
- Premier League channels: USA Network, TNT Sports, Sky Sports Premier League, Sky Sports Main Event, Sky Sports Football
- Champions League channels: CBS Sports Golazo, TNT Sports 1, TNT Sports 2, Paramount Network
- LaLiga channels: LaLiga TV, beIN Sports
- Featured match headline and channel selection
- Stream manager accepts a URL or an iframe embed snippet
- Optional Firebase Authentication + Realtime Database integration for owner sign-in and live updates
- Responsive layout for phones and desktops

## Run it
This is a static site. Open `index.html` locally or publish the repository with GitHub Pages:
1. Open **Settings → Pages** in this repository.
2. Select **Deploy from a branch**, choose `main` and `/ (root)`, then Save.
3. Wait for GitHub Pages to publish the site.

## Stream links
Only add streams you are authorized to access and embed. Many broadcaster sites block playback inside third-party iframes; use their official watch page where appropriate.

## Browser-only demo mode
Without Firebase, changes are saved in the current browser only using local storage. This is useful for previewing, but **it is not owner-only and does not sync between visitors**.

## Enable secure owner editing and live sync
1. Create a Firebase project and register a Web app.
2. Enable **Authentication → Email/Password** and create the owner's user account.
3. Create a **Realtime Database**.
4. In the app's Streams screen, paste the Firebase web app config JSON and the owner's exact email, then click **Connect Firebase** and **Sign in as owner**.
5. Set Realtime Database rules so public visitors can read the published stream configuration but only the owner can write. Example below: replace the email placeholder with the exact owner email.

```json
{
  "rules": {
    "streamtv": {
      "publicState": {
        ".read": true,
        ".write": "auth != null && auth.token.email === 'REPLACE_WITH_OWNER_EMAIL'"
      }
    }
  }
}
```

These rules make the shared state readable by visitors and writable only by the configured owner account. Do not place service-account keys, private API secrets, or passwords in the frontend. Review Firebase security rules before publishing.

## Important
The included client checks are for user experience only. Firebase Realtime Database security rules are the actual access control. Do not use a frontend-only PIN as a security boundary.
