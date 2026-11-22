/** Standalone PEVV. This is the whole app: no galaxy, no towns, no Luci. */
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '../styles/globals.css';
import { initLocale } from './host/locale';
import { PevvStandalone } from './ui/PevvStandalone';

document.documentElement.classList.add('lv-pevv-app');
void initLocale();
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <PevvStandalone />
  </StrictMode>,
);
