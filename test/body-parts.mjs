/**
 * Unit tests for the structure-first message fetch.
 *
 * getMessage no longer downloads the whole RFC822 source; it walks
 * BODYSTRUCTURE to find the text part, reads attachment metadata off the same
 * tree, and parses References out of a header-only fetch. Those three walks are
 * pure functions of data the server sends, so they are tested here without an
 * IMAP server. The wire behaviour around them (download + maxBytes) is
 * imapflow's, and is covered by test/smoke.mjs against GreenMail.
 *
 * The References tests compare against mailparser on the same raw message,
 * because that is what the old code path used: threading must not shift.
 *
 * Usage: node test/body-parts.mjs   (expects a built dist/)
 */
import { simpleParser } from 'mailparser';
import { Mailbox } from '../dist/imap/mailbox.js';

let passed = 0;
let failed = 0;
const failures = [];

function check(name, condition, detail = '') {
  if (condition) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    failures.push(`${name}${detail ? ` — ${detail}` : ''}`);
    console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// The helpers under test read only MAX_BODY_CHARS, and never touch the socket.
const mailbox = new Mailbox({ MAX_BODY_CHARS: 20000, ALLOWED_FOLDERS: [] }, null);
const pick = (node) => mailbox.pickTextPart(node);
const attachments = (node) => mailbox.collectAttachments(node);
const references = (raw) => mailbox.parseReferences(Buffer.from(raw, 'utf8'));

// --- BODYSTRUCTURE fixtures, shaped as imapflow's parser emits them --------
// The root node of a non-multipart message carries no `part`; children of a
// multipart are numbered "1", "2", "2.1" and so on.

const plainOnly = { type: 'text/plain', encoding: '7bit', size: 420 };

const alternative = {
  type: 'multipart/alternative',
  childNodes: [
    { part: '1', type: 'text/plain', encoding: 'quoted-printable', size: 420 },
    { part: '2', type: 'text/html', encoding: 'quoted-printable', size: 1800 }
  ]
};

const htmlOnly = {
  type: 'multipart/alternative',
  childNodes: [{ part: '1', type: 'text/html', encoding: 'base64', size: 2400 }]
};

const mixedWithPdf = {
  type: 'multipart/mixed',
  childNodes: [
    { part: '1', type: 'text/plain', encoding: '7bit', size: 300 },
    {
      part: '2',
      type: 'application/pdf',
      encoding: 'base64',
      size: 1_400_000,
      disposition: 'attachment',
      dispositionParameters: { filename: 'invoice.pdf' }
    }
  ]
};

// A newsletter: text + html alternative, inline image, and a real attachment.
const nested = {
  type: 'multipart/mixed',
  childNodes: [
    {
      part: '1',
      type: 'multipart/related',
      childNodes: [
        {
          part: '1.1',
          type: 'multipart/alternative',
          childNodes: [
            { part: '1.1.1', type: 'text/plain', encoding: '7bit', size: 900 },
            { part: '1.1.2', type: 'text/html', encoding: 'quoted-printable', size: 9000 }
          ]
        },
        {
          part: '1.2',
          type: 'image/png',
          encoding: 'base64',
          size: 40_000,
          disposition: 'inline',
          dispositionParameters: { filename: 'logo.png' }
        }
      ]
    },
    {
      part: '2',
      type: 'application/zip',
      encoding: 'base64',
      size: 800,
      disposition: 'attachment',
      parameters: { name: 'legacy-name.zip' }
    }
  ]
};

// A .txt attachment and nothing else: there is no body to render.
const attachmentOnly = {
  type: 'multipart/mixed',
  childNodes: [
    {
      part: '1',
      type: 'text/plain',
      encoding: '7bit',
      size: 120,
      disposition: 'attachment',
      dispositionParameters: { filename: 'notes.txt' }
    }
  ]
};

// A forwarded mail carried as message/rfc822.
const forwarded = {
  type: 'multipart/mixed',
  childNodes: [
    { part: '1', type: 'text/plain', encoding: '7bit', size: 80 },
    {
      part: '2',
      type: 'message/rfc822',
      size: 5000,
      childNodes: [{ part: '2.1', type: 'text/plain', encoding: '7bit', size: 4000 }]
    }
  ]
};

console.log('\npickTextPart');
check('a non-multipart body is addressed as part 1', eq(pick(plainOnly), { part: '1', type: 'text/plain' }),
  JSON.stringify(pick(plainOnly)));
check('text/plain wins over text/html in an alternative',
  eq(pick(alternative), { part: '1', type: 'text/plain' }), JSON.stringify(pick(alternative)));
check('text/html is used when that is all there is',
  eq(pick(htmlOnly), { part: '1', type: 'text/html' }), JSON.stringify(pick(htmlOnly)));
check('an attached pdf is not mistaken for the body',
  eq(pick(mixedWithPdf), { part: '1', type: 'text/plain' }), JSON.stringify(pick(mixedWithPdf)));
check('the text part is found through nested multiparts',
  eq(pick(nested), { part: '1.1.1', type: 'text/plain' }), JSON.stringify(pick(nested)));
check('a .txt attachment is not treated as the body (falls back to a full parse)',
  pick(attachmentOnly) === undefined, JSON.stringify(pick(attachmentOnly)));
check('a forwarded message does not supply the body',
  eq(pick(forwarded), { part: '1', type: 'text/plain' }), JSON.stringify(pick(forwarded)));
check('an empty structure yields no part', pick(undefined) === undefined);

console.log('\ncollectAttachments');
const pdf = attachments(mixedWithPdf);
check('one attachment is reported', pdf.length === 1, JSON.stringify(pdf));
check('its filename comes from the disposition', pdf[0]?.filename === 'invoice.pdf');
check('its content type is carried through', pdf[0]?.contentType === 'application/pdf');
check('base64 size is reported decoded, not encoded',
  pdf[0]?.sizeBytes === Math.floor((1_400_000 * 3) / 4), String(pdf[0]?.sizeBytes));

const nestedAttachments = attachments(nested);
check('inline images are not listed as attachments', nestedAttachments.length === 1,
  JSON.stringify(nestedAttachments));
check('a filename falls back to the content-type name parameter',
  nestedAttachments[0]?.filename === 'legacy-name.zip', JSON.stringify(nestedAttachments[0]));
check('a message with no attachments reports none', attachments(alternative).length === 0);
check('an empty structure reports none', attachments(undefined).length === 0);

console.log('\nparseReferences (compared against mailparser on the same message)');

/** Builds a raw message, then checks both paths agree on its References. */
async function agreesWithMailparser(name, headerBlock) {
  const raw = `${headerBlock}\r\n\r\nbody text\r\n`;
  const parsed = await simpleParser(Buffer.from(raw, 'utf8'));
  const viaMailparser = [].concat(parsed.references ?? []);
  const viaHeaders = references(headerBlock);
  check(name, eq(viaHeaders, viaMailparser), `ours ${JSON.stringify(viaHeaders)} vs mailparser ${JSON.stringify(viaMailparser)}`);
  return viaHeaders;
}

await agreesWithMailparser(
  'a single reference',
  ['From: a@example.com', 'Message-ID: <c@example.com>', 'References: <a@example.com>'].join('\r\n')
);

const folded = await agreesWithMailparser(
  'a References header folded across three lines',
  [
    'From: a@example.com',
    'Message-ID: <d@example.com>',
    'References: <a@example.com>',
    "\t<b@example.com>",
    ' <c@example.com>'
  ].join('\r\n')
);
check('the folded header yields all three ids in order',
  eq(folded, ['<a@example.com>', '<b@example.com>', '<c@example.com>']), JSON.stringify(folded));

await agreesWithMailparser(
  'ids written without angle brackets are wrapped',
  ['From: a@example.com', 'References: a@example.com b@example.com'].join('\r\n')
);

await agreesWithMailparser(
  'no References header at all',
  ['From: a@example.com', 'In-Reply-To: <a@example.com>'].join('\r\n')
);

// Header names are case-insensitive, and a header-only fetch may return them
// in whatever case the server stored.
check('the header name is matched case-insensitively',
  eq(references('REFERENCES: <a@example.com>\r\n'), ['<a@example.com>']),
  JSON.stringify(references('REFERENCES: <a@example.com>\r\n')));
check('an absent header block yields no references', eq(mailbox.parseReferences(undefined), []));
check('in-reply-to alone does not become a reference',
  eq(references('In-Reply-To: <a@example.com>\r\n'), []));

console.log(`\n${passed} passed, ${failed} failed`);
if (failures.length > 0) {
  console.log('\nFailures:');
  for (const f of failures) console.log(`  - ${f}`);
}
process.exit(failed === 0 ? 0 : 1);
