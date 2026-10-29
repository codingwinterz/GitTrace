// The two formats share every scene: a composition passes `layout`, and each
// scene reads it here to choose its arrangement. The data (claims, scan) and
// the storyboard timing are the same for both.
import React, { createContext, useContext } from "react";

export type Layout = "square" | "wide";

const LayoutContext = createContext<Layout>("square");

export const LayoutProvider: React.FC<{ layout: Layout; children: React.ReactNode }> = ({ layout, children }) => (
  <LayoutContext.Provider value={layout}>{children}</LayoutContext.Provider>
);

export const useLayout = (): Layout => useContext(LayoutContext);

// Safe margin from every edge: 80 px in the square (1080), 96 px in the wide (1920x1080).
export const useMargin = (): number => (useLayout() === "wide" ? 96 : 80);
