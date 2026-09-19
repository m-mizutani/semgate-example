package frontend

import "embed"

// StaticFiles holds the built SPA assets. The dist directory is produced by the
// frontend build (pnpm build); an empty dist with a .gitkeep keeps the embed
// valid before the first build.
//
//go:embed all:dist
var StaticFiles embed.FS
