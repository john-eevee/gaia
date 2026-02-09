import React from 'react';
import Link from '@docusaurus/Link';

export default function Home() {
  return (
    <main style={{ padding: '4rem', textAlign: 'center' }}>
      <h1>Welcome to Gaia</h1>
      <p>Distributed smart agriculture cooperative</p>
      <p>
        <Link to="/docs/intro">Get started with the docs →</Link>
      </p>
    </main>
  );
}
