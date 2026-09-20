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
    expect(screen.getByText(/One target you are allowed to attack/)).toBeInTheDocument()
    expect(screen.getByRole('note')).toHaveTextContent('intentionally vulnerable')
    expect(screen.getByRole('note')).toHaveTextContent('logged')
  })
})
