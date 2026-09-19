import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, it, expect } from 'vitest'
import Home from './Home'

describe('Home', () => {
  it('renders the tagline and the disclaimer', () => {
    render(
      <MemoryRouter>
        <Home />
      </MemoryRouter>,
    )
    expect(screen.getByText(/Everything lands/)).toBeInTheDocument()
    expect(screen.getByRole('note')).toHaveTextContent('intentionally vulnerable')
    expect(screen.getByRole('note')).toHaveTextContent('logged')
  })
})
