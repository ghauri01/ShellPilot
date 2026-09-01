import { useEffect } from 'react'
import { ArrowLeft, ArrowRight, Check, Compass } from 'lucide-react'
import { useOnboarding } from '../../store/onboarding'
import { useApp } from '../../store/app'
import { clsx } from '../../lib/format'
import { TOUR_STEPS } from './tourSteps'

// A first-run walkthrough, mounted once at the app root.
//
// Deliberately not a modal over a dimmed screen: each step switches to the
// view it describes and the card sits in a corner, so the feature is visible
// while it is explained. A tour that hides the app while describing it teaches
// nothing you can act on.
export function OnboardingTour(): React.JSX.Element | null {
  const open = useOnboarding((s) => s.open)
  const step = useOnboarding((s) => s.step)
  const next = useOnboarding((s) => s.next)
  const back = useOnboarding((s) => s.back)
  const goTo = useOnboarding((s) => s.goTo)
  const finish = useOnboarding((s) => s.finish)
  const openIfFirstRun = useOnboarding((s) => s.openIfFirstRun)
  const setActivity = useApp((s) => s.setActivity)

  useEffect(() => {
    openIfFirstRun()
  }, [openIfFirstRun])

  const current = TOUR_STEPS[step]

  // Move the app to whatever this step is about.
  useEffect(() => {
    if (open && current?.view) setActivity(current.view)
  }, [open, current?.view, setActivity])

  // Escape closes it, the same as Skip — a tour you cannot dismiss with the
  // obvious key is a trap.
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') finish()
      if (e.key === 'ArrowRight') {
        if (step < TOUR_STEPS.length - 1) next()
        else finish()
      }
      if (e.key === 'ArrowLeft') back()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, step, next, back, finish])

  if (!open || !current) return null
  const last = step === TOUR_STEPS.length - 1

  return (
    <div className="tour-card" role="dialog" aria-label="ShellPilot walkthrough">
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <Compass size={16} style={{ color: 'var(--accent)' }} />
        <b>{current.title}</b>
        <span className="spacer" />
        <span className="server-meta">
          {step + 1} / {TOUR_STEPS.length}
        </span>
      </div>

      <div className="s-desc" style={{ marginTop: 8 }}>
        {current.body}
      </div>

      {current.action && (
        <div className="tour-action">
          <Check size={12} /> {current.action}
        </div>
      )}

      <div className="tour-dots">
        {TOUR_STEPS.map((s, i) => (
          <button
            key={s.id}
            className={clsx('tour-dot', i === step && 'active')}
            aria-label={s.title}
            onClick={() => goTo(i)}
          />
        ))}
      </div>

      <div className="row" style={{ gap: 8, marginTop: 10 }}>
        <button className="btn sm" disabled={step === 0} onClick={back}>
          <ArrowLeft size={13} /> Back
        </button>
        <button className="btn sm primary" onClick={() => (last ? finish() : next())}>
          {last ? (
            <>
              <Check size={13} /> Done
            </>
          ) : (
            <>
              Next <ArrowRight size={13} />
            </>
          )}
        </button>
        <span className="spacer" />
        {!last && (
          <button className="btn sm ghost" onClick={finish}>
            Skip
          </button>
        )}
      </div>
    </div>
  )
}
