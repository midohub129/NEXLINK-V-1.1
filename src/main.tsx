import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { AppContainerProvider } from './presentation/context/ContainerContext';
import './index.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AppContainerProvider>
      <App />
    </AppContainerProvider>
  </StrictMode>
);
