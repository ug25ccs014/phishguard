type Props = { eyebrow?: string; title: string; description?: string; align?: 'left' | 'center'; headingLevel?: 'h1' | 'h2' }
export function SectionHeader({ eyebrow, title, description, align = 'left', headingLevel = 'h2' }: Props) {
  const Heading = headingLevel

  return (
    <div className={align === 'center' ? 'mx-auto max-w-2xl text-center' : 'max-w-2xl'}>
      {eyebrow && <div className="eyebrow mb-3">{eyebrow}</div>}
      <Heading className="text-3xl font-bold tracking-tight text-white sm:text-4xl">{title}</Heading>
      {description && <p className="mt-4 text-base leading-7 text-slate-400">{description}</p>}
    </div>
  )
}
