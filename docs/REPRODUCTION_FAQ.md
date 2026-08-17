# Independent reproduction FAQ

## Does a matching ZIP prove reproducibility?

No. ZIP bytes can differ because of compression implementations. The verifier
requires raw executable and declared public-content equality.

## Does a matching executable prove the build machine was trusted?

No. It is evidence that two environments produced the same bytes, not proof that
both were uncompromised.

## Why is the reference binary never run?

The downloaded candidate is untrusted input to the verifier. Inspection is
sufficient for byte comparison and avoids an unnecessary execution boundary.

## Why is reproduced self-test execution optional?

It runs code with the operator's privileges and is not sandboxed. The operator
must review and opt in explicitly.

## Does a maintainer's second machine count as independent?

Not automatically. Administrative separation and reviewer independence must be
stated and assessed under issue #7.

## Does this complete the release gate?

No. Linux, macOS, and Windows reproduction evidence, recovery drills, and an
independent security review remain required.
