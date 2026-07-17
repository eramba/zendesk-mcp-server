import { runOAuthAdmin } from '../dist/oauth/admin.js'

process.exitCode = await runOAuthAdmin(process.argv.slice(2))
