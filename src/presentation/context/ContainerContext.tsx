import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { createAppContainer, type AppContainer } from '../../application/container';
import type { LifecyclePhase } from '../../application/lifecycle/lifecycleManager';

interface ContainerContextValue {
  container: AppContainer;
  phase: LifecyclePhase;
}

const ContainerContext = createContext<ContainerContextValue | null>(null);

export function AppContainerProvider({ children }: { children: ReactNode }) {
  const container = useMemo(() => createAppContainer(), []);
  const [phase, setPhase] = useState<LifecyclePhase>(() =>
    container.lifecycleManager.getPhase()
  );

  useEffect(() => {
    const unsub = container.lifecycleManager.subscribe(() => {
      setPhase(container.lifecycleManager.getPhase());
    });

    void container.lifecycleManager.startup().catch(() => {
      // Captured by ErrorManager inside LifecycleManager
    });

    return () => {
      unsub();
      void container.lifecycleManager.shutdown();
    };
  }, [container]);

  return (
    <ContainerContext.Provider value={{ container, phase }}>
      {children}
    </ContainerContext.Provider>
  );
}

export function useAppContainer(): ContainerContextValue {
  const ctx = useContext(ContainerContext);
  if (!ctx) {
    throw new Error('useAppContainer must be used within AppContainerProvider');
  }
  return ctx;
}
