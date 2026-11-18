import faviconUrl from '@/assets/favicon.png'
import { Button } from '@/components/ui/button'
import { Field, FieldGroup, FieldLabel } from '@/components/ui/field'
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput, InputGroupText } from '@/components/ui/input-group'
import { showToast } from '@/lib/store'
import { IconArrowRight, IconEye, IconEyeOff, IconLock } from '@tabler/icons-react'
import { useState } from 'react'

interface LoginFormProps {
  mode: 'login' | 'setup'
  onAuth: () => void
}

export function LoginForm({ mode, onAuth }: LoginFormProps) {
  const [password, setPassword] = useState('')
  const [visible, setVisible] = useState(false)
  const [token, setToken] = useState('')
  const [invalid, setInvalid] = useState(false)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.SyntheticEvent) => {
    e.preventDefault()
    if (!password) return
    setLoading(true)
    setInvalid(false)
    try {
      const res = await fetch(mode === 'setup' ? '/api/auth/setup' : '/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(mode === 'setup' ? { password, token } : { password }),
      })
      const data = await res.json()
      if (data.success) {
        onAuth()
      } else {
        setInvalid(true)
        showToast(data.error ?? 'Ошибка', 'error')
      }
    } catch {
      showToast('Ошибка соединения', 'error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bg-muted dark:bg-background flex min-h-dvh items-center justify-center p-4">
      <div className="bg-card ring-foreground/10 mx-auto w-full max-w-md space-y-6 rounded-2xl border p-6 shadow-lg">
        <div className="space-y-2 text-left">
          <div className="flex items-center gap-3">
            <img src={faviconUrl} alt="XkeenWRT" className="size-9" />
            <h1 className="text-3xl font-semibold">XkeenWRT</h1>
          </div>
          <p className="text-muted-foreground pt-1 text-sm text-pretty">
            {mode === 'setup'
              ? 'Установите пароль (не менее 12 символов) и введите токен из локального файла, путь к которому выводит сервер. На OpenWrt обычно используется /etc/xkeenwrt/bootstrap-token.'
              : 'Введите пароль для входа'}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-5">
          <FieldGroup>
            <Field data-invalid={invalid || undefined}>
              <FieldLabel htmlFor="password">Пароль</FieldLabel>
              <InputGroup>
                <InputGroupAddon className="pl-2.5">
                  <InputGroupText className="text-muted-foreground/80">
                    <IconLock size={16} aria-hidden="true" />
                  </InputGroupText>
                </InputGroupAddon>
                <InputGroupInput
                  id="password"
                  placeholder="Введите пароль..."
                  type={visible ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value)
                    setInvalid(false)
                  }}
                  aria-invalid={invalid || undefined}
                  autoFocus
                  minLength={mode === 'setup' ? 12 : undefined}
                  required
                />
                <InputGroupAddon align="inline-end" className="pr-2.5">
                  <InputGroupButton
                    type="button"
                    size="icon-xs"
                    variant="ghost"
                    onClick={() => setVisible((v) => !v)}
                    aria-label={visible ? 'Скрыть пароль' : 'Показать пароль'}
                    aria-pressed={visible}
                    className="text-muted-foreground/80 hover:text-foreground"
                  >
                    {visible ? <IconEyeOff size={16} aria-hidden="true" /> : <IconEye size={16} aria-hidden="true" />}
                  </InputGroupButton>
                </InputGroupAddon>
              </InputGroup>
            </Field>
          </FieldGroup>

          {mode === 'setup' && (
            <Field>
              <FieldLabel htmlFor="token">Токен первоначальной настройки</FieldLabel>
              <InputGroup>
                <InputGroupInput
                  id="token"
                  type="password"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  autoComplete="off"
                  required
                />
              </InputGroup>
            </Field>
          )}

          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? '...' : mode === 'setup' ? 'Установить пароль' : 'Войти'}
            {!loading && <IconArrowRight size={16} />}
          </Button>
        </form>
      </div>
    </div>
  )
}
