export const GLOBAL_STYLES = `
.tab-bar {
  background: #111111;
  border-bottom: 1px solid #2a2a2a;
  position: sticky;
  top: 0;
  z-index: 10;
}

.tab-btn {
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  border-radius: 0;
  color: #888888;
  padding: 0.75rem 1rem;
  font-size: 0.875rem;
  font-weight: 600;
  white-space: nowrap;
  cursor: pointer;
}

.tab-btn:hover { color: #ffffff; }
.tab-btn.active {
  color: #7c3aed;
  border-bottom-color: #7c3aed;
}

.intro-strip {
  color: #888888;
  border-bottom: 1px solid #2a2a2a;
  padding: 0.5rem 1rem;
  font-size: 0.75rem;
}

.intro-strip a {
  color: #888888;
}

.intro-strip a:hover {
  color: #ffffff;
}

.chip {
  display: inline-block;
  padding: 0.125rem 0.5rem;
  border-radius: 2px;
  font-size: 0.75rem;
  font-weight: 600;
  color: #888888;
  background: none;
  border: 1px solid #2a2a2a;
  cursor: pointer;
}

.chip:hover {
  color: #ffffff;
  border-color: #888888;
}

.chip.active {
  color: #ffffff;
  border-color: #7c3aed;
  background: rgba(124, 58, 237, 0.15);
}
`;
