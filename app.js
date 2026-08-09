/**
 * Matt's Poems - Feed Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  // App State
  const state = {
    poems: [...POEMS_DATA],
    favorites: typeof FAVORITES_DATA !== 'undefined' ? [...FAVORITES_DATA] : [],
    expandedIds: new Set(),
    theme: localStorage.getItem('matspoems_theme') || 'light'
  };

  // DOM Elements
  const poemFeedEl = document.getElementById('poemFeed');
  const favoritesFeedEl = document.getElementById('favoritesFeed');
  const themeSelectEl = document.getElementById('themeSelect');
  const toastEl = document.getElementById('toast');

  // Initialize Theme
  applyTheme(state.theme);
  if (themeSelectEl) themeSelectEl.value = state.theme;

  // Render Initial Feed
  renderFeed();

  // Unsent Letter Controller
  const unsentContainerEl = document.getElementById('unsentLetterContainer');
  let unsentStep = sessionStorage.getItem('unsent_letter_unlocked') === 'true' ? 'unlocked' : 1;

  renderUnsentLetterSection();

  function renderUnsentLetterSection() {
    if (!unsentContainerEl || typeof UNSENT_LETTER_DATA === 'undefined') return;
    unsentContainerEl.innerHTML = '';
    const letterCard = createPoemCard(UNSENT_LETTER_DATA);
    unsentContainerEl.appendChild(letterCard);
  }

  // Theme Listener
  if (themeSelectEl) {
    themeSelectEl.addEventListener('change', (e) => {
      state.theme = e.target.value;
      localStorage.setItem('matspoems_theme', state.theme);
      applyTheme(state.theme);
    });
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
  }

  function renderFeed() {
    if (poemFeedEl) {
      poemFeedEl.innerHTML = '';
      state.poems.forEach(poem => {
        poemFeedEl.appendChild(createPoemCard(poem));
      });
    }
    if (favoritesFeedEl) {
      favoritesFeedEl.innerHTML = '';
      state.favorites.forEach(poem => {
        favoritesFeedEl.appendChild(createPoemCard(poem));
      });
    }
  }

  function createPoemCard(poem) {
    const isExpanded = state.expandedIds.has(poem.id);
    const excerpt = poem.excerpt || (poem.stanzas[0] ? poem.stanzas[0].join(' ') : '');
    const metaText = poem.author ? escapeHTML(poem.author) : formatDate(poem.date);

    const card = document.createElement('article');
    card.className = `poem-card ${isExpanded ? 'expanded' : ''}`;

    const stanzasHTML = poem.stanzas.map(stanza => {
      const linesHTML = stanza.map(line => `<div class="poem-line">${escapeHTML(line) || '&nbsp;'}</div>`).join('');
      return `<div class="stanza">${linesHTML}</div>`;
    }).join('');

    card.innerHTML = `
      <button class="poem-header" aria-expanded="${isExpanded}">
        <div class="poem-header-main">
          <div class="poem-title-row">
            <h2 class="poem-title">${escapeHTML(poem.title)}</h2>
            <span class="poem-date">${metaText}</span>
          </div>
          <div class="poem-excerpt">${escapeHTML(excerpt)}</div>
        </div>
        <div class="expand-icon-wrapper" aria-hidden="true">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="6 9 12 15 18 9"></polyline>
          </svg>
        </div>
      </button>

      <div class="poem-body-container">
        <div class="poem-body-inner">
          <div class="poem-content">
            <div class="stanzas-wrapper">
              ${stanzasHTML}
            </div>
          </div>
        </div>
      </div>
    `;

    // Embed Question Box inside Unsent Letter card if locked
    if (poem.id === 'unsent-letter' && unsentStep !== 'unlocked') {
      const stanzasWrapper = card.querySelector('.stanzas-wrapper');
      if (stanzasWrapper) {
        const questionText = unsentStep === 1
          ? 'What is your name?'
          : "Who's shotglass?";

        stanzasWrapper.innerHTML = `
          <div class="unsent-letter-card">
            <div class="lock-step-indicator">Question ${unsentStep} of 2</div>
            <h3 class="lock-question">${questionText}</h3>
            <form class="lock-form" id="lockForm">
              <div class="lock-input-group">
                <input type="text" class="lock-input" id="lockInput" placeholder="Enter answer..." autocomplete="off" required />
                <button type="submit" class="lock-btn">Submit</button>
              </div>
              <div class="lock-error" id="lockError">Incorrect answer. Try again.</div>
            </form>
          </div>
        `;

        const formEl = stanzasWrapper.querySelector('#lockForm');
        const inputEl = stanzasWrapper.querySelector('#lockInput');
        const errorEl = stanzasWrapper.querySelector('#lockError');

        if (formEl) {
          formEl.addEventListener('submit', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const val = inputEl.value.trim().toLowerCase();

            if (unsentStep === 1) {
              if (val === 'emma') {
                unsentStep = 2;
                state.expandedIds.add('unsent-letter');
                renderUnsentLetterSection();
              } else {
                errorEl.classList.add('show');
                inputEl.select();
              }
            } else if (unsentStep === 2) {
              const validGrandmaAnswers = ['grandma', 'grandmas', "grandma's", 'grandma’s'];
              if (validGrandmaAnswers.includes(val)) {
                unsentStep = 'unlocked';
                sessionStorage.setItem('unsent_letter_unlocked', 'true');
                state.expandedIds.add('unsent-letter');
                renderUnsentLetterSection();
              } else {
                errorEl.classList.add('show');
                inputEl.select();
              }
            }
          });
        }
      }
    }

    // Click header to toggle card
    const headerBtn = card.querySelector('.poem-header');
    headerBtn.addEventListener('click', () => {
      if (state.expandedIds.has(poem.id)) {
        state.expandedIds.delete(poem.id);
        card.classList.remove('expanded');
        headerBtn.setAttribute('aria-expanded', 'false');
      } else {
        state.expandedIds.add(poem.id);
        card.classList.add('expanded');
        headerBtn.setAttribute('aria-expanded', 'true');
      }
    });

    return card;
  }

  function showToast(msg) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.classList.add('show');
    setTimeout(() => toastEl.classList.remove('show'), 2000);
  }

  function formatDate(dateStr) {
    if (!dateStr) return '';
    const d = new Date(dateStr + 'T00:00:00');
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }

  function escapeHTML(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
});
