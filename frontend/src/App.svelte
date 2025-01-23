<script>
  import { onMount } from 'svelte';
  import D1Logo from './assets/D1_GUI.ico'

  let tomlFile = null;
  let statusMessage = 'Awaiting input...';

  function handleFileUpload(event) {
    const file = event.target.files[0];
    if (file && file.name.endsWith('.toml')) {
      tomlFile = file;
      statusMessage = `Loaded file: ${file.name}`;
    } else {
      statusMessage = 'Please upload a valid .toml file';
    }
  }

  function useCloudflareWrangler() {
    if (!tomlFile) {
      statusMessage = 'Please upload a TOML file first!';
      return;
    }
    statusMessage = 'Using Cloudflare Wrangler...';
  }

  function useCloudflareAPI() {
    statusMessage = 'Using Cloudflare API...';
  }

  onMount(() => {
    console.log('App initialized');
  });
</script>

<main>
  <header>
    <img src={D1Logo} alt="App Logo" class="logo" />
  </header>

  <section class="upload">
    <label for="toml-upload" class="file-label">Upload TOML Config:</label>
    <input id="toml-upload" type="file" accept=".toml" on:change={handleFileUpload} />
  </section>

  <section class="controls">
    <button class="btn" on:click={useCloudflareWrangler}>Use Wrangler</button>
    <button class="btn" on:click={useCloudflareAPI}>Use Cloudflare API</button>
  </section>

  <section class="status">
    <p>Status: {statusMessage}</p>
  </section>
</main>

<style>
  main {
    font-family: Arial, sans-serif;
    text-align: center;
    padding: 2rem;
  }

  .logo {
    height: 6em;
    transition: transform 300ms ease-in-out;
  }

  .logo:hover {
    transform: scale(1.1);
    filter: drop-shadow(0 0 2em #3365feaa);
  }

  .file-label {
    display: block;
    margin-top: 1rem;
    font-weight: bold;
  }

  .controls {
    margin-top: 1.5rem;
  }

  .btn {
    background: #3365fe;
    color: white;
    border: none;
    padding: 0.75rem 1.5rem;
    margin: 0 0.5rem;
    border-radius: 5px;
    cursor: pointer;
    transition: background 200ms;
  }

  .btn:hover {
    background: #2749c4;
  }

  .status {
    margin-top: 2rem;
    color: #888;
  }
</style>
