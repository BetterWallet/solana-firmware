export const posts = [
  {
    slug: 'solana-offline-signing-model',
    no: '01',
    category: 'Solana',
    date: '2026-04-28',
    title: 'Solana makes Keystone UR signing feel native on a Pi.',
    dek: 'Animated `ur:sol-sign-request` / `ur:sol-signature` frames map cleanly to camera-in, display-out. Better Wallet Pi uses that shape to keep signing offline without hiding the handoff from the person approving it.',
    body: [
      'The transport is still just light between two machines. A compatible browser wallet fountain-encodes the sign request; the Pi reassembles CBOR, parses the Solana intent, and only then asks for a physical confirm. The return path is the same choreography in reverse.',
      'That rhythm is friendly to an air-gapped wallet: the online computer prepares and broadcasts; the Pi scans, verifies, waits for GPIO, signs, and shows the result. The boundary stays visible the whole time.',
      'Better Wallet Pi still treats this as a prototype. The goal is not to claim a finished consumer product — it is to show a small, auditable signing loop where Solana is the first-class path, not an afterthought bolted onto a different chain stack.',
    ],
  },
  {
    slug: 'air-gap-as-product-decision',
    no: '02',
    category: 'Security',
    date: '2026-04-28',
    title: 'An air gap is a product decision, not a decoration.',
    dek: 'The useful part of being offline is not the theatre. It is the boring, repeatable fact that every transaction crosses a visible human checkpoint.',
    body: [
      'Better Wallet Pi treats the camera and screen as the complete communication surface. The online machine may render a request as light. The offline device may answer with light. Everything else is excluded from the core flow.',
      'That choice changes the product. There is no background sync to trust, no driver quietly asking for access, and no cable that becomes a second protocol surface. The user experience is narrower, but the boundary is easier to reason about.',
      'The tradeoff is deliberate. An offline signer should be slower than a browser extension. It should ask you to look, compare, and approve by hand. That friction is part of the security model.',
    ],
  },
  {
    slug: 'pi-prototype-not-vault',
    no: '03',
    category: 'Build log',
    date: '2026-04-28',
    title: 'The Raspberry Pi is a good prototype, not a magic vault.',
    dek: 'Commodity hardware makes the design approachable and auditable. It also means the security story has to be plain about what has not been hardened yet.',
    body: [
      'The Pi gives the project a camera stack, display stack, GPIO buttons, and a well-documented Linux environment. That makes it a strong reference platform for experimenting with offline transaction review and QR transport.',
      'It does not make side-channel risk disappear. It does not replace an external audit. It does not turn a hobby build into a hardened commercial hardware wallet by itself.',
      'The honest version of Better Wallet Pi is a buildable reference design with a narrow network surface, explicit key-material boundaries, and a bias toward verification before trust.',
    ],
  },
];

export type BlogPost = (typeof posts)[number];
