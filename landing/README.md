# Better Wallet Pi — Landing Page

Static marketing site for [solana-firmware](https://github.com/BetterWallet/solana-firmware). Built with [Astro](https://astro.build) + [Tailwind CSS](https://tailwindcss.com), deployed to Firebase Hosting.

## Develop

```sh
npm install
npm run dev          # http://localhost:4321
```

## Build

```sh
npm run build        # outputs to dist/
npm run preview      # serve the production build locally
```

## Deploy to Firebase Hosting

One-time setup:

```sh
npm install -g firebase-tools
firebase login
cp .firebaserc.example .firebaserc
# edit .firebaserc and set your project id
```

Then:

```sh
npm run deploy       # builds and runs `firebase deploy --only hosting`
```

## Structure

```
src/
├── pages/index.astro        # composes all sections
├── layouts/Layout.astro     # <head>, fonts, OG tags
├── components/              # one .astro file per section
└── styles/global.css        # Tailwind + design tokens
```
