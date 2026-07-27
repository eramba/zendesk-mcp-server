import assert from 'node:assert/strict'
import test from 'node:test'

import { ZendeskClient } from '../dist/zendesk-client.js'

function response(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

function workflowClient(bodies) {
  const requests = []
  return {
    requests,
    client: new ZendeskClient({
      subdomain: 'acme',
      auth: {
        kind: 'oauth',
        accessToken: 'access-token-sentinel',
        onUnauthorized: async () => assert.fail('fresh token must not refresh'),
      },
      fetch: async (input) => {
        requests.push(String(input))
        const body = bodies.shift()
        assert.notEqual(body, undefined, 'unexpected Zendesk request')
        return response(body)
      },
    }),
  }
}

test('workflow methods use cursor endpoints and return only opaque next cursors', async () => {
  const { client, requests } = workflowClient([
    {
      views: [{ id: 44, title: 'My unsolved', active: true, default: false }],
      meta: { has_more: true },
      links: {
        next: 'https://acme.zendesk.com/api/v2/views.json?page%5Bsize%5D=25&page%5Bafter%5D=view-next',
      },
    },
    {
      tickets: [{ id: 36870, group_id: 73 }],
      meta: { has_more: false },
      links: { next: null },
    },
    {
      groups: [{ id: 73, name: 'First level', default: true, deleted: false }],
      meta: { has_more: false },
      links: { next: null },
    },
    {
      group_memberships: [{ id: 900, user_id: 101, group_id: 73, default: true }],
      users: [{ id: 101, name: 'Agent', email: 'agent@example.test', role: 'agent' }],
      meta: { has_more: false },
      links: { next: null },
    },
  ])

  const views = await client.listViews({ pageSize: 25 })
  const tickets = await client.listViewTickets(44, { pageSize: 25, after: 'view-next' })
  const groups = await client.listAssignableGroups({ pageSize: 25 })
  const members = await client.listGroupMembers(73, { pageSize: 25 })

  assert.equal(requests[0], 'https://acme.zendesk.com/api/v2/views.json?active=true&page%5Bsize%5D=25')
  assert.equal(requests[1], 'https://acme.zendesk.com/api/v2/views/44/tickets.json?page%5Bsize%5D=25&page%5Bafter%5D=view-next')
  assert.equal(requests[2], 'https://acme.zendesk.com/api/v2/groups/assignable.json?page%5Bsize%5D=25')
  assert.equal(requests[3], 'https://acme.zendesk.com/api/v2/groups/73/memberships.json?include=users&page%5Bsize%5D=25')

  assert.deepEqual(views, {
    items: [{ id: 44, title: 'My unsolved', description: null, active: true, default: false, position: null, created_at: null, updated_at: null }],
    page_size: 25,
    has_more: true,
    next_cursor: 'view-next',
  })
  assert.equal(tickets.items[0].group_id, 73)
  assert.equal(groups.items[0].name, 'First level')
  assert.deepEqual(members.items[0], {
    id: 900,
    user_id: 101,
    group_id: 73,
    default: true,
    created_at: null,
    updated_at: null,
  })
  assert.equal(members.users[0].email, 'agent@example.test')
})

test('workflow cursor extraction rejects off-origin next links', async () => {
  const { client } = workflowClient([{
    views: [],
    meta: { has_more: true },
    links: { next: 'https://attacker.example.test/api/v2/views?page%5Bafter%5D=secret' },
  }])

  const error = await client.listViews({ pageSize: 25 }).catch((caught) => caught)
  assert.equal(error.category, 'invalid_response')
})
